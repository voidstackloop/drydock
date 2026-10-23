#pragma once
// What `leakcheck --version` says about this build. CMake (and
// build-windows.ps1) write leakcheck_version.h from VERSION and git; the
// fallbacks are for a compiler command typed by hand. Nothing here is a
// copyright year or a marketing number: a bug report is only useful with the
// exact build in it.

#if defined(__has_include)
#if __has_include("leakcheck_version.h")
#include "leakcheck_version.h"
#endif
#endif

#ifndef LEAKCHECK_VERSION
#define LEAKCHECK_VERSION "0.0.0-dev"
#endif
#ifndef LEAKCHECK_GIT_HASH
#define LEAKCHECK_GIT_HASH "unknown"
#endif
#ifndef LEAKCHECK_BUILD_TYPE
#define LEAKCHECK_BUILD_TYPE "unknown"
#endif

#if defined(_WIN32)
#if defined(_M_ARM64) || defined(__aarch64__)
#define LEAKCHECK_PLATFORM "windows-arm64"
#else
#define LEAKCHECK_PLATFORM "windows-x86_64"
#endif
#elif defined(__APPLE__)
#if defined(__aarch64__)
#define LEAKCHECK_PLATFORM "macos-arm64"
#else
#define LEAKCHECK_PLATFORM "macos-x86_64"
#endif
#elif defined(__linux__)
#if defined(__aarch64__)
#define LEAKCHECK_PLATFORM "linux-arm64"
#else
#define LEAKCHECK_PLATFORM "linux-x86_64"
#endif
#else
#define LEAKCHECK_PLATFORM "unknown"
#endif
