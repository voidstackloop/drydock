#pragma once

// Names shared by the injected runtime (writer) and the leakcheck CLI (reader).
// Both sides compile this header, so a rename cannot drift out of sync.

namespace lcproto {

inline constexpr int kVersion = 1;

inline constexpr const char *kEnvReport = "LEAKCHECK_REPORT";
inline constexpr const char *kEnvRootPid = "LEAKCHECK_ROOT_PID";
inline constexpr const char *kEnvQuarantineMb = "LEAKCHECK_QUARANTINE_MB";
inline constexpr const char *kEnvStackDepth = "LEAKCHECK_STACK_DEPTH";
inline constexpr const char *kEnvGuardEvery = "LEAKCHECK_GUARD_EVERY";
inline constexpr const char *kEnvAbort = "LEAKCHECK_ABORT";
inline constexpr const char *kEnvFastUnwind = "LEAKCHECK_FAST_UNWIND";
inline constexpr const char *kEnvLeaks = "LEAKCHECK_LEAKS";
inline constexpr const char *kEnvReachable = "LEAKCHECK_REACHABLE";
inline constexpr const char *kEnvTraceChildren = "LEAKCHECK_TRACE_CHILDREN";
// --malware: also look for the 100 malware families (see malware.h). Off by default.
inline constexpr const char *kEnvMalware = "LEAKCHECK_MALWARE";
// Set by the user, not the CLI: also report pointers to freed blocks left in
// live data at exit (off by default: noisy for programs that tear down).
inline constexpr const char *kEnvDangling = "LEAKCHECK_DANGLING";

#ifdef _WIN32
inline constexpr const char *kLibName = "leakcheck_preload.dll";
#elif defined(__APPLE__)
inline constexpr const char *kLibName = "libleakcheck_preload.dylib";
#else
inline constexpr const char *kLibName = "libleakcheck_preload.so";
#endif

// Finding types.
inline constexpr const char *kDoubleFree = "double-free";
inline constexpr const char *kInvalidFree = "invalid-free";
inline constexpr const char *kUseAfterFree = "heap-use-after-free";
inline constexpr const char *kOverflow = "heap-buffer-overflow";
inline constexpr const char *kUnderflow = "heap-buffer-underflow";
inline constexpr const char *kMismatch = "alloc-dealloc-mismatch";
inline constexpr const char *kSizeMismatch = "free-size-mismatch";
inline constexpr const char *kLeak = "memory-leak";
inline constexpr const char *kResourceLeak = "resource-leak";
inline constexpr const char *kDoubleClose = "double-close";
inline constexpr const char *kUseAfterClose = "use-after-close";
inline constexpr const char *kUseAfterMove = "use-after-move";
inline constexpr const char *kLockOrder = "lock-order-inversion";
inline constexpr const char *kDoubleLock = "double-lock";
inline constexpr const char *kLockLeak = "lock-leak";
inline constexpr const char *kSignalUnsafe = "signal-unsafe-call";
inline constexpr const char *kInheritedFd = "inherited-descriptor";
inline constexpr const char *kDangling = "dangling-pointer";
inline constexpr const char *kUnlockedWait = "unlocked-wait";
inline constexpr const char *kForeignUnlock = "foreign-unlock";
inline constexpr const char *kDoubleJoin = "double-join";
inline constexpr const char *kDestroyLocked = "destroy-locked";
inline constexpr const char *kUseAfterDestroy = "use-after-destroy";
inline constexpr const char *kUncheckedStream = "unchecked-stream";
inline constexpr const char *kThreadStackArg = "thread-stack-argument";
inline constexpr const char *kSpuriousWakeup = "spurious-wakeup";
inline constexpr const char *kOrphanedLock = "orphaned-lock";
inline constexpr const char *kThreadUnsafe = "thread-unsafe-call";
inline constexpr const char *kSigpipe = "sigpipe-exposure";
inline constexpr const char *kEofSpin = "socket-eof-spin";
inline constexpr const char *kEagain = "socket-eagain-spin";
inline constexpr const char *kBindReuse = "bind-without-reuseaddr";
inline constexpr const char *kFdLimit = "descriptor-limit";
inline constexpr const char *kSelectOverflow = "select-overflow";
// What a trojan, backdoor or dropper does (dynamic), and what marks one (scan).
inline constexpr const char *kReverseShell = "reverse-shell";
inline constexpr const char *kDropper = "dropper";
inline constexpr const char *kFileless = "fileless-exec";
inline constexpr const char *kPersistence = "persistence";
inline constexpr const char *kCredAccess = "credential-access";
inline constexpr const char *kInjection = "process-injection";
inline constexpr const char *kAntiAnalysis = "anti-analysis";
inline constexpr const char *kPrivEsc = "privilege-escalation";
inline constexpr const char *kLogTamper = "log-tampering";
inline constexpr const char *kDestructive = "destructive-command";
inline constexpr const char *kMiner = "cryptominer";
inline constexpr const char *kMasquerade = "masquerade";
inline constexpr const char *kObfuscated = "obfuscated-code";
inline constexpr const char *kRansom = "ransomware-pattern";
inline constexpr const char *kNetScan = "network-scan";
inline constexpr const char *kSystemTamper = "system-tampering";
// What a scan of a file finds (see scan.cpp).
inline constexpr const char *kMalware = "malware-signature";
inline constexpr const char *kDisguised = "disguised-executable";
inline constexpr const char *kSuspiciousBin = "suspicious-binary";
// --ai: the trained classifier's verdict on a Windows program.
inline constexpr const char *kAiClassifier = "ai-classifier";
// Security weaknesses found in the source (static).
inline constexpr const char *kFormatString = "format-string";
inline constexpr const char *kCmdInjection = "command-injection";
inline constexpr const char *kUnboundedCopy = "unbounded-copy";
inline constexpr const char *kUnboundedAlloca = "unbounded-alloca";
inline constexpr const char *kUnsafeFunction = "unsafe-function";
inline constexpr const char *kHardcodedSecret = "hardcoded-secret";
inline constexpr const char *kToctou = "toctou-race";
inline constexpr const char *kBadPermissions = "insecure-permissions";
inline constexpr const char *kWeakCrypto = "weak-crypto";
inline constexpr const char *kSizeofPointer = "sizeof-pointer";
inline constexpr const char *kAllocSizeOverflow = "alloc-size-overflow";
inline constexpr const char *kTlsNoVerify = "tls-no-verify";
inline constexpr const char *kPathTraversal = "path-traversal";
inline constexpr const char *kSqlInjection = "sql-injection";
inline constexpr const char *kNullDeref = "null-dereference";
inline constexpr const char *kInsecurePrng = "insecure-prng";
inline constexpr const char *kSsrf = "ssrf";
inline constexpr const char *kXss = "xss";
inline constexpr const char *kOobRead = "out-of-bounds-read";
inline constexpr const char *kOobWrite = "out-of-bounds-write";
inline constexpr const char *kOffByOne = "off-by-one";
inline constexpr const char *kIntegerOverflow = "integer-overflow";
inline constexpr const char *kInsecureTempFile = "insecure-tempfile";
inline constexpr const char *kHardcodedKeyIv = "hardcoded-key-iv";
inline constexpr const char *kUncheckedSecurityReturn = "unchecked-security-return";
inline constexpr const char *kUnclearedSensitive = "uncleared-sensitive-data";
inline constexpr const char *kReturnStackAddress = "return-stack-address";
inline constexpr const char *kUninitVariable = "uninitialized-variable";
inline constexpr const char *kTimingAttack = "timing-attack";
inline constexpr const char *kZipSlip = "zip-slip";
inline constexpr const char *kInsecureDeserialization = "insecure-deserialization";
inline constexpr const char *kInsecureBindAll = "insecure-bind-all";
inline constexpr const char *kHighEntropySecret = "high-entropy-secret";
// One finding type per malware family that --malware looks for (the five families
// that already had a type keep it: ransomware-pattern, fileless-exec, dropper,
// credential-access, cryptominer). malware.h lists all 100.
inline constexpr const char *kVirus = "virus";
inline constexpr const char *kWorm = "worm";
inline constexpr const char *kTrojan = "trojan-horse";
inline constexpr const char *kSpyware = "spyware";
inline constexpr const char *kAdware = "adware";
inline constexpr const char *kRootkit = "rootkit";
inline constexpr const char *kKeylogger = "keylogger";
inline constexpr const char *kBackdoor = "backdoor";
inline constexpr const char *kRat = "remote-access-trojan";
inline constexpr const char *kBootkit = "bootkit";
inline constexpr const char *kPolymorphic = "polymorphic-code";
inline constexpr const char *kMetamorphic = "metamorphic-code";
inline constexpr const char *kLogicBomb = "logic-bomb";
inline constexpr const char *kDownloader = "downloader";
inline constexpr const char *kLoader = "loader";
inline constexpr const char *kExploit = "exploit-code";
inline constexpr const char *kLotl = "living-off-the-land";
inline constexpr const char *kBanking = "banking-trojan";
inline constexpr const char *kInfostealer = "infostealer";
inline constexpr const char *kFormGrabber = "form-grabber";
inline constexpr const char *kBrowserHijack = "browser-hijacker";
inline constexpr const char *kClipHijack = "clipboard-hijacker";
inline constexpr const char *kPos = "pos-malware";
inline constexpr const char *kAtm = "atm-malware";
inline constexpr const char *kMobileBanking = "mobile-banking-malware";
inline constexpr const char *kBotnet = "botnet";
inline constexpr const char *kDdos = "ddos-tool";
inline constexpr const char *kIrcBot = "irc-bot";
inline constexpr const char *kIot = "iot-malware";
inline constexpr const char *kWiper = "wiper";
inline constexpr const char *kFileWiper = "file-wiper";
inline constexpr const char *kPropagation = "network-propagation";
inline constexpr const char *kProxy = "proxy-malware";
inline constexpr const char *kDnsHijack = "dns-hijack";
inline constexpr const char *kBrowserInject = "browser-injection";
inline constexpr const char *kMobileSpyware = "mobile-spyware";
inline constexpr const char *kMobileAdware = "mobile-adware";
inline constexpr const char *kSmsTrojan = "sms-trojan";
inline constexpr const char *kSimTargeting = "sim-targeting";
inline constexpr const char *kFileInfector = "file-infector";
inline constexpr const char *kMacro = "macro-malware";
inline constexpr const char *kScriptMalware = "script-malware";
inline constexpr const char *kSupplyChain = "supply-chain";
inline constexpr const char *kFirmware = "firmware-malware";
inline constexpr const char *kFakeAv = "fake-antivirus";
inline constexpr const char *kExtortion = "data-extortion";
inline constexpr const char *kScreenLocker = "screen-locker";
inline constexpr const char *kMicEavesdrop = "microphone-eavesdropper";
inline constexpr const char *kCamHijack = "webcam-hijacker";
inline constexpr const char *kScreenGrabber = "screenshot-grabber";
inline constexpr const char *kMalExtension = "malicious-extension";
inline constexpr const char *kSeoPoison = "seo-poisoning";
inline constexpr const char *kClickFraud = "click-fraud";
inline constexpr const char *kDialer = "toll-fraud-dialer";
inline constexpr const char *kFleeceware = "fleeceware";
inline constexpr const char *kRecoveryBlock = "recovery-blocker";
inline constexpr const char *kIcsMalware = "ics-scada-malware";
inline constexpr const char *kCloudMalware = "cloud-malware";
inline constexpr const char *kContainerEscape = "container-escape";
inline constexpr const char *kHypervisorEscape = "hypervisor-escape";
inline constexpr const char *kC2Beacon = "c2-beacon";
inline constexpr const char *kStager = "reflective-stager";
inline constexpr const char *kProcessHollowing = "process-hollowing";
inline constexpr const char *kProcessDoppel = "process-doppelganging";
inline constexpr const char *kDllHijack = "dll-sideloading";
inline constexpr const char *kComHijack = "com-hijacking";
inline constexpr const char *kBackupWiper = "backup-wiper";
inline constexpr const char *kSeedStealer = "seed-phrase-stealer";
inline constexpr const char *kTokenStealer = "token-stealer";
inline constexpr const char *kGameStealer = "gaming-account-stealer";
inline constexpr const char *kEmailStealer = "email-account-stealer";
inline constexpr const char *kVpnStealer = "vpn-credential-stealer";
inline constexpr const char *kKerberosAttack = "kerberos-stealer";
inline constexpr const char *kCookieHijack = "cookie-hijacker";
inline constexpr const char *kMfaBypass = "mfa-bypass-tool";
inline constexpr const char *kWebShell = "web-shell";
inline constexpr const char *kWebMiner = "web-miner";
inline constexpr const char *kMalvertising = "malvertising";
inline constexpr const char *kDigitalSkimmer = "digital-skimmer";
inline constexpr const char *kPolyglot = "polyglot-malware";
inline constexpr const char *kCertAbuse = "certificate-abuse";
inline constexpr const char *kByovd = "bring-your-own-vulnerable-driver";
inline constexpr const char *kSecurityDisabler = "security-disabler";
inline constexpr const char *kLogWiper = "event-log-wiper";
inline constexpr const char *kMbrLocker = "mbr-locker";
inline constexpr const char *kVbrDestroyer = "partition-destroyer";
inline constexpr const char *kNetSniffer = "network-sniffer";
inline constexpr const char *kArpSpoofer = "arp-spoofer";
inline constexpr const char *kReconTool = "reconnaissance-tool";
inline constexpr const char *kBruteForcer = "brute-force-tool";
inline constexpr const char *kDepConfusion = "dependency-confusion";
inline constexpr const char *kBuildTrojan = "build-trojan";
inline constexpr const char *kKernelExploit = "kernel-exploit";
inline constexpr const char *kHardwareImplant = "hardware-implant";
inline constexpr const char *kAiMalware = "ai-malware";

// Leak categories (valgrind terminology).
inline constexpr const char *kCatDefinite = "definite";
inline constexpr const char *kCatIndirect = "indirect";
inline constexpr const char *kCatPossible = "possible";
inline constexpr const char *kCatReachable = "reachable";

// What a resource finding is about.
inline constexpr const char *kCatFd = "fd";
inline constexpr const char *kCatStream = "stream"; // FILE *
inline constexpr const char *kCatDir = "dir";       // DIR *
inline constexpr const char *kCatThread = "thread";
inline constexpr const char *kCatProcess = "process";
inline constexpr const char *kCatLock = "lock";     // a pthread mutex
inline constexpr const char *kCatSignal = "signal"; // inside a signal handler
inline constexpr const char *kCatHeap = "heap";     // points into the heap
inline constexpr const char *kCatSecurity = "security"; // behaves like malware
inline constexpr const char *kCatScan = "scan";         // a file scan found it

// clang-format off
// Record grammar (one record per line, fields separated by single spaces):
//   H v=<n> pid=<pid> exe=<path to end of line>
//   M <pid> <module-id> <path to end of line>
//   B type=<t> pid=<pid> addr=<hex> size=<n> tid=<n> key=<hex>
//     [cat=<c> blocks=<n> bytes=<n>] msg=<text to end of line>
//   S <role> <module-id>:<hex-offset> ...   role: a(ccess) | l(alloc) | f(ree)
//   X                                       ends the B record
//   D key=<hex> count=<n>                   extra occurrences of a deduped B
//   T pid=<pid> allocs=<n> frees=<n> bytes=<n> live_blocks=<n> live_bytes=<n>
//     peak_bytes=<n> dropped=<n> scanned=<0|1>
//   Z pid=<pid>                             clean end of stream
// clang-format on
// Frame offsets are relative to the module load bias, for the address
// (return address - 1), so they can be fed to addr2line unchanged.

} // namespace lcproto
