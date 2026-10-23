// Sockets on Windows (Winsock): the handle of each one, a socket closed twice or
// used after it was closed, a read loop that never stops at end of file or spins
// on a socket with nothing to read, the addresses connected to (a scan) and the
// names looked up (a host that imitates a trusted one).
#include <winsock2.h>
#include <ws2tcpip.h>

#include "behavior.h"
#include "protocol.h"
#include "report.h"
#include "resources.h"
#include "stacks.h"
#include "win_hooks.h"

#include <string.h>

namespace lc::win {
namespace {

using res::Kind;

bool g_on;

bool on() { return g_on && !tl_in_hook; }

uint64_t id(SOCKET s) { return uint64_t(s); }

void made(SOCKET s, const char *how) {
    if (s == INVALID_SOCKET || !on())
        return;
    HookGuard hg;
    ErrnoSaver es;
    res::opened(Kind::Fd, id(s), how);
}

// A call failed with WSAENOTSOCK: use after close, if we saw it closed.
void bad_socket(SOCKET s, const char *how) {
    if (!on() || int(GetLastError()) != WSAENOTSOCK)
        return;
    HookGuard hg;
    ErrnoSaver es;
    res::used_closed(id(s), how);
}

// ---- reads that go nowhere -------------------------------------------------------------------

constexpr uint32_t kSpin = 1000;
constexpr size_t kSlots = 256;
struct Count {
    uintptr_t s;
    uint32_t zero, again;
};
Count g_counts[kSlots];
SpinLock g_counts_lock;

Count &count_of(SOCKET s) {
    Count &c = g_counts[(uintptr_t(s) >> 2) & (kSlots - 1)];
    if (c.s != uintptr_t(s)) {
        c.s = uintptr_t(s);
        c.zero = c.again = 0;
    }
    return c;
}

// Datagram and raw sockets are remembered when they are made; the rest are streams.
SOCKET g_dgram[64];
SpinLock g_dgram_lock;

void note_type(SOCKET s, int type) {
    if (s == INVALID_SOCKET || (type != SOCK_DGRAM && type != SOCK_RAW))
        return;
    LockGuard g(g_dgram_lock);
    for (SOCKET &v : g_dgram)
        if (!v) {
            v = s;
            return;
        }
}

bool is_stream(SOCKET s) {
    LockGuard g(g_dgram_lock);
    for (SOCKET v : g_dgram)
        if (v == s)
            return false;
    return true;
}

void spin(SOCKET s, const char *type, const char *how, const char *what) {
    HookGuard hg;
    ErrnoSaver es;
    if (!is_stream(s))
        return;
    char m[256];
    Buf msg(m, sizeof m);
    msg.s(how).s(what).u(kSpin).s(" times in a row on socket ").u(id(s));
    report::Finding f;
    f.type = type;
    f.category = lcproto::kCatFd;
    f.addr = id(s);
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    report::emit(f);
}

void read_result(SOCKET s, int n, int want, const char *how) {
    if (!on())
        return;
    const int err = n == SOCKET_ERROR ? int(GetLastError()) : 0;
    uint32_t z = 0, a = 0;
    {
        LockGuard g(g_counts_lock);
        Count &c = count_of(s);
        c.zero = n == 0 && want > 0 ? c.zero + 1 : 0;
        c.again = err == WSAEWOULDBLOCK ? c.again + 1 : 0;
        z = c.zero;
        a = c.again;
    }
    if (z == kSpin)
        spin(s, lcproto::kEofSpin, how,
             " returned 0 (the peer closed the connection) and the loop keeps reading it: stop at end of file; ");
    if (a == kSpin)
        spin(s, lcproto::kEagain, how,
             " said there was nothing to read and the loop does not wait (poll or select first); ");
    if (n == SOCKET_ERROR) {
        SetLastError(err); // (the counting above may have touched it)
        bad_socket(s, how);
    }
}

// ---- hooks -----------------------------------------------------------------------------------------

decltype(&socket) real_socket;
SOCKET WSAAPI hk_socket(int af, int t, int p) {
    SOCKET s = real_socket(af, t, p);
    note_type(s, t);
    made(s, "socket()");
    return s;
}
decltype(&WSASocketA) real_WSASocketA;
SOCKET WSAAPI hk_WSASocketA(int af, int t, int p, LPWSAPROTOCOL_INFOA i, GROUP g, DWORD f) {
    SOCKET s = real_WSASocketA(af, t, p, i, g, f);
    note_type(s, t);
    made(s, "WSASocket()");
    return s;
}
decltype(&WSASocketW) real_WSASocketW;
SOCKET WSAAPI hk_WSASocketW(int af, int t, int p, LPWSAPROTOCOL_INFOW i, GROUP g, DWORD f) {
    SOCKET s = real_WSASocketW(af, t, p, i, g, f);
    note_type(s, t);
    made(s, "WSASocket()");
    return s;
}
decltype(&accept) real_accept;
SOCKET WSAAPI hk_accept(SOCKET l, sockaddr *a, int *n) {
    SOCKET s = real_accept(l, a, n);
    if (s == INVALID_SOCKET)
        bad_socket(l, "accept()");
    made(s, "accept()");
    return s;
}

decltype(&closesocket) real_closesocket;
int WSAAPI hk_closesocket(SOCKET s) {
    if (!on())
        return real_closesocket(s);
    int r = real_closesocket(s);
    const int e = int(GetLastError());
    {
        HookGuard hg;
        if (r == 0) {
            res::closed(Kind::Fd, id(s));
            LockGuard g(g_dgram_lock);
            for (SOCKET &v : g_dgram)
                if (v == s)
                    v = 0;
        }
        else if (e == WSAENOTSOCK)
            res::close_failed(id(s), "closesocket()");
    }
    SetLastError(e);
    return r;
}

// A scan is a hundred different addresses in ten seconds.
decltype(&connect) real_connect;
int WSAAPI hk_connect(SOCKET s, const sockaddr *a, int len) {
    if (on()) {
        ErrnoSaver es;
        behavior::connecting(a, unsigned(len));
    }
    int r = real_connect(s, a, len);
    if (r == SOCKET_ERROR) {
        const int e = int(GetLastError());
        if (on() && e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAENOTSOCK) {
            HookGuard hg;
            res::socket_failed(id(s), "connect()", e);
        }
        SetLastError(e);
        bad_socket(s, "connect()");
    }
    return r;
}
decltype(&WSAConnect) real_WSAConnect;
int WSAAPI hk_WSAConnect(SOCKET s, const sockaddr *a, int len, LPWSABUF c, LPWSABUF d, LPQOS q, LPQOS g) {
    if (on()) {
        ErrnoSaver es;
        behavior::connecting(a, unsigned(len));
    }
    int r = real_WSAConnect(s, a, len, c, d, q, g);
    if (r == SOCKET_ERROR)
        bad_socket(s, "WSAConnect()");
    return r;
}
decltype(&bind) real_bind;
int WSAAPI hk_bind(SOCKET s, const sockaddr *a, int len) {
    int r = real_bind(s, a, len);
    if (r == SOCKET_ERROR)
        bad_socket(s, "bind()");
    return r;
}
decltype(&send) real_send;
int WSAAPI hk_send(SOCKET s, const char *b, int n, int f) {
    int r = real_send(s, b, n, f);
    if (r == SOCKET_ERROR)
        bad_socket(s, "send()");
    return r;
}
decltype(&recv) real_recv;
int WSAAPI hk_recv(SOCKET s, char *b, int n, int f) {
    int r = real_recv(s, b, n, f);
    if (r <= 0)
        read_result(s, r, n, "recv()");
    else if (on()) {
        LockGuard g(g_counts_lock);
        count_of(s).again = 0;
    }
    return r;
}
decltype(&recvfrom) real_recvfrom;
int WSAAPI hk_recvfrom(SOCKET s, char *b, int n, int f, sockaddr *a, int *l) {
    int r = real_recvfrom(s, b, n, f, a, l);
    if (r <= 0)
        read_result(s, r, n, "recvfrom()");
    return r;
}

// ---- names -------------------------------------------------------------------------------------------

void looked_up(const char *name, const char *how) {
    if (!name || !on())
        return;
    ErrnoSaver es;
    behavior::host(name, how);
}
decltype(&getaddrinfo) real_getaddrinfo;
INT WSAAPI hk_getaddrinfo(PCSTR n, PCSTR s, const ADDRINFOA *h, PADDRINFOA *r) {
    looked_up(n, "getaddrinfo()");
    return real_getaddrinfo(n, s, h, r);
}
decltype(&GetAddrInfoW) real_GetAddrInfoW;
INT WSAAPI hk_GetAddrInfoW(PCWSTR n, PCWSTR s, const ADDRINFOW *h, PADDRINFOW *r) {
    if (n && on()) {
        char a[256];
        int k = WideCharToMultiByte(CP_UTF8, 0, n, -1, a, sizeof a - 1, nullptr, nullptr);
        a[k > 0 ? k - 1 : 0] = 0;
        looked_up(a, "GetAddrInfo()");
    }
    return real_GetAddrInfoW(n, s, h, r);
}
decltype(&gethostbyname) real_gethostbyname;
hostent *WSAAPI hk_gethostbyname(const char *n) {
    looked_up(n, "gethostbyname()");
    return real_gethostbyname(n);
}

#define HK(NAME) {#NAME, reinterpret_cast<void *>(hk_##NAME), (void **)&real_##NAME, false}
const Hook g_hooks[] = {
    HK(socket), HK(WSASocketA), HK(WSASocketW), HK(accept), HK(closesocket), HK(connect), HK(WSAConnect),
    HK(bind), HK(send), HK(recv), HK(recvfrom), HK(getaddrinfo), HK(GetAddrInfoW), HK(gethostbyname),
};
#undef HK

} // namespace

const Hook *net_hooks(size_t *n) {
    *n = sizeof g_hooks / sizeof g_hooks[0];
    return g_hooks;
}

void net_on() { g_on = true; }

} // namespace lc::win
