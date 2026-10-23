#pragma once
// The heap functions as Windows implements them. The hooks call these; the
// runtime's own allocations and frees go through them too, so they are never
// tracked.
#include <windows.h>

namespace lc::win {

extern LPVOID(WINAPI *real_HeapAlloc)(HANDLE, DWORD, SIZE_T);
extern BOOL(WINAPI *real_HeapFree)(HANDLE, DWORD, LPVOID);
extern LPVOID(WINAPI *real_HeapReAlloc)(HANDLE, DWORD, LPVOID, SIZE_T);
extern SIZE_T(WINAPI *real_HeapSize)(HANDLE, DWORD, LPCVOID);
extern BOOL(WINAPI *real_HeapValidate)(HANDLE, DWORD, LPCVOID);

HANDLE process_heap();
// A pointer the runtime has no record of that the process heap knows as a busy
// block: allocated before the runtime was loaded, or by Windows itself.
bool untracked_heap_block(const void *p);

} // namespace lc::win
