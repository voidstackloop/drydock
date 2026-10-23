cmake_minimum_required(VERSION 3.28)
# VERSION is the one place the release number lives: CMake, the Windows script
# and the release workflow all read it, so `--version` cannot disagree with the tag.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" LEAKCHECK_VERSION LIMIT_COUNT 1)
project(leakcheck VERSION ${LEAKCHECK_VERSION} LANGUAGES C CXX)
include(GNUInstallDirs)
if(WIN32)
    enable_language(RC) # the manifest that makes leakcheck.exe's strings UTF-8
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

# Unix preload sources. Linux builds them as an LD_PRELOAD .so; macOS as a
# DYLD_INSERT_LIBRARIES dylib with darwin_interpose.c.
set(lc_preload_unix
    dynamic-engine/src/preload/behavior.cpp
    dynamic-engine/src/preload/behavior_io.cpp
    dynamic-engine/src/preload/blocks.cpp
    dynamic-engine/src/preload/fd_io.cpp
    dynamic-engine/src/preload/guard.cpp
    dynamic-engine/src/preload/heap.cpp
    dynamic-engine/src/preload/init.cpp
    dynamic-engine/src/preload/interpose.cpp
    dynamic-engine/src/preload/interpose_io.cpp
    dynamic-engine/src/preload/leakscan.cpp
    dynamic-engine/src/preload/locks.cpp
    dynamic-engine/src/preload/report.cpp
    dynamic-engine/src/preload/resources.cpp
    dynamic-engine/src/preload/rt.cpp
    dynamic-engine/src/preload/signals.cpp
    dynamic-engine/src/preload/sockets.cpp
    dynamic-engine/src/preload/stacks.cpp
    dynamic-engine/src/preload/threads.cpp
    dynamic-engine/src/preload/unsafe_libc.cpp
)

if(WIN32)
    # The runtime injected into the target on Windows (leakcheck_preload.dll). It hooks the heap
    # of the process, so like the Linux library it must not depend on the C++ runtime.
    add_library(leakcheck_preload SHARED
        dynamic-engine/src/preload/behavior.cpp
        dynamic-engine/src/preload/blocks.cpp
        dynamic-engine/src/preload/heap.cpp
        dynamic-engine/src/preload/leakscan.cpp
        dynamic-engine/src/preload/report.cpp
        dynamic-engine/src/preload/resources.cpp
        dynamic-engine/src/preload/stacks.cpp
        dynamic-engine/src/win/behavior_win.cpp
        dynamic-engine/src/win/guard_win.cpp
        dynamic-engine/src/win/init_win.cpp
        dynamic-engine/src/win/locks_win.cpp
        dynamic-engine/src/win/mem_win.cpp
        dynamic-engine/src/win/net_win.cpp
        dynamic-engine/src/win/res_win.cpp
        dynamic-engine/src/win/rt_win.cpp
        dynamic-engine/src/win/threads_win.cpp
        dynamic-engine/src/win/win_hooks.cpp
    )
    set_target_properties(leakcheck_preload PROPERTIES PREFIX "")
    target_include_directories(leakcheck_preload PRIVATE
        dynamic-engine/src/preload dynamic-engine/src/win shared/include)
    target_compile_options(leakcheck_preload PRIVATE
        -Wall -Wextra -g -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-omit-frame-pointer)
    target_link_options(leakcheck_preload PRIVATE -nostdlib++ -static-libgcc)
elseif(APPLE)
add_library(leakcheck_preload SHARED ${lc_preload_unix}
    dynamic-engine/src/preload/darwin_interpose.c)
target_include_directories(leakcheck_preload PRIVATE dynamic-engine/src/preload shared/include)
target_compile_options(leakcheck_preload PRIVATE
    -Wall -Wextra -g
    -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-omit-frame-pointer
    -fvisibility=hidden -fvisibility-inlines-hidden
    -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free)
target_link_options(leakcheck_preload PRIVATE -dynamiclib -nostdlib++)
else()
# The runtime injected into the target with LD_PRELOAD. It is the target's
# malloc, so it must not depend on the C++ runtime or on exceptions.
add_library(leakcheck_preload SHARED ${lc_preload_unix})
target_include_directories(leakcheck_preload PRIVATE dynamic-engine/src/preload shared/include)
target_compile_options(leakcheck_preload PRIVATE
    -Wall -Wextra -g
    # g++ 16 turns on _FORTIFY_SOURCE at -O2, and the fortified <setjmp.h>
    # renames longjmp, _longjmp and siglongjmp all to __longjmp_chk.
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
    -fno-exceptions -fno-rtti -fno-threadsafe-statics -fno-omit-frame-pointer
    -fvisibility=hidden -fvisibility-inlines-hidden
    -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free)
target_link_options(leakcheck_preload PRIVATE -nostdlib++ -Wl,--as-needed -Wl,-z,defs)
target_link_libraries(leakcheck_preload PRIVATE ${CMAKE_DL_LIBS})
endif()

# Everything the CLI does, as a library so unit tests can link it.
if(WIN32)
    set(dynamic_engine_source dynamic-engine/src/dynamic_engine_win.cpp)
else()
    set(dynamic_engine_source dynamic-engine/src/dynamic_engine.cpp)
endif()
add_library(leakcheck_core STATIC
    ${dynamic_engine_source}
    static-engine/src/analyzer.cpp
    static-engine/src/lexer.cpp
    static-engine/src/parser.cpp
    static-engine/src/scan.cpp
    static-engine/src/ai_features.cpp
    static-engine/src/ai_model.cpp
    static-engine/src/malware_scan.cpp
    static-engine/src/malware_table.cpp
    static-engine/src/scan_engine.cpp
    static-engine/src/security.cpp
    static-engine/src/static_engine.cpp
    reporter/src/compose.cpp
    reporter/src/render_console.cpp
    reporter/src/render_json.cpp
    reporter/src/render_sarif.cpp
    reporter/src/report.cpp
    reporter/src/runtime_stream.cpp
    reporter/src/suppress.cpp
    reporter/src/symbolize.cpp
)
target_include_directories(leakcheck_core PUBLIC
    static-engine/include dynamic-engine/include reporter/include shared/include)
# (the scan reads and scans several files at a time)
find_package(Threads REQUIRED)
target_link_libraries(leakcheck_core PUBLIC Threads::Threads)
target_compile_options(leakcheck_core PRIVATE -Wall -Wextra -g)

add_executable(leakcheck src/main.cpp)
target_link_libraries(leakcheck PRIVATE leakcheck_core)
if(WIN32)
    target_sources(leakcheck PRIVATE src/windows/leakcheck.rc)
    target_link_options(leakcheck PRIVATE -static) # no MinGW DLLs next to leakcheck.exe
endif()
target_compile_options(leakcheck PRIVATE -Wall -Wextra -g)
if(NOT WIN32)
    add_dependencies(leakcheck leakcheck_preload)
endif()

# --version: the release, the commit and the build type, so a report names the
# exact binary. A source tarball without git has "unknown" rather than a lie.
execute_process(COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE LEAKCHECK_GIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT LEAKCHECK_GIT_HASH)
    set(LEAKCHECK_GIT_HASH "unknown")
endif()
file(WRITE "${CMAKE_BINARY_DIR}/leakcheck_version.h"
    "#pragma once\n#define LEAKCHECK_VERSION \"${LEAKCHECK_VERSION}\"\n"
    "#define LEAKCHECK_GIT_HASH \"${LEAKCHECK_GIT_HASH}\"\n"
    "#define LEAKCHECK_BUILD_TYPE \"${CMAKE_BUILD_TYPE}\"\n")
target_include_directories(leakcheck PRIVATE ${CMAKE_BINARY_DIR})
target_compile_definitions(leakcheck PRIVATE
    LEAKCHECK_MODEL_PATH="${CMAKE_INSTALL_FULL_DATADIR}/leakcheck/model/pe-malware.ai")

option(LEAKCHECK_BUILD_TESTS "Build the test programs and register tests" ON)
if(LEAKCHECK_BUILD_TESTS)
    enable_testing()
    find_package(Threads REQUIRED)
    find_package(Python3 COMPONENTS Interpreter)

    # Deliberately buggy programs, built for readable stacks.
    set(test_dir ${CMAKE_BINARY_DIR}/test-programs)
    if(WIN32)
        set(test_programs no_bugs.c leaks.c heap_errors.c stress.c cxx_errors.cpp mixed_bugs.cpp
            threads.cpp win_resources.c win_locks.c win_locks_cxx.cpp win_behavior.c win_sockets.c)
    elseif(APPLE)
        set(test_programs no_bugs.c leaks.c heap_errors.c processes.c stress.c
            cxx_errors.cpp mixed_bugs.cpp threads.cpp signals.c dangling.c unsafe_libc.c)
    else()
        set(test_programs no_bugs.c leaks.c heap_errors.c processes.c alloc_api.c stress.c
            cxx_errors.cpp mixed_bugs.cpp threads.cpp resources.c locks.c
            signals.c dangling.c unsafe_libc.c sigpipe.c sockets.c behavior.c)
    endif()
    foreach(src ${test_programs})
        get_filename_component(name ${src} NAME_WE)
        add_executable(test_${name} tests/dynamic/programs/${src})
        set_target_properties(test_${name} PROPERTIES
            OUTPUT_NAME ${name} RUNTIME_OUTPUT_DIRECTORY ${test_dir})
        target_compile_options(test_${name} PRIVATE -g -O0 -fno-omit-frame-pointer -w)
        target_link_libraries(test_${name} PRIVATE Threads::Threads)
    endforeach()
    if(WIN32)
        target_link_libraries(test_win_behavior PRIVATE ws2_32)
        target_link_libraries(test_win_sockets PRIVATE ws2_32)
    elseif(NOT APPLE)
        target_link_libraries(test_behavior PRIVATE anl) # getaddrinfo_a()
        # Same program as a fixed-address executable: exercises address mapping.
        add_executable(test_heap_errors_nopie tests/dynamic/programs/heap_errors.c)
        set_target_properties(test_heap_errors_nopie PROPERTIES
            OUTPUT_NAME heap_errors_nopie RUNTIME_OUTPUT_DIRECTORY ${test_dir}
            POSITION_INDEPENDENT_CODE OFF)
        target_compile_options(test_heap_errors_nopie PRIVATE -g -O0 -fno-pie -w)
        target_link_options(test_heap_errors_nopie PRIVATE -no-pie)
    endif()

    # Unit tests: white-box checks of each component.
    add_executable(unit_static tests/unit/static_test.cpp)
    target_include_directories(unit_static PRIVATE static-engine/src)
    target_link_libraries(unit_static PRIVATE leakcheck_core)

    add_executable(unit_scan tests/unit/scan_test.cpp)
    target_include_directories(unit_scan PRIVATE static-engine/src)
    target_link_libraries(unit_scan PRIVATE leakcheck_core)

    add_executable(unit_ai tests/unit/ai_test.cpp)
    target_include_directories(unit_ai PRIVATE static-engine/src)
    target_link_libraries(unit_ai PRIVATE leakcheck_core)

    add_executable(unit_reporter tests/unit/reporter_test.cpp)
    target_include_directories(unit_reporter PRIVATE reporter/src)
    target_link_libraries(unit_reporter PRIVATE leakcheck_core)

    # The runtime's sources, minus the exported allocator and the process
    # hooks, built into an ordinary program so its logic can be driven directly.
    if(NOT WIN32 AND NOT APPLE)
    add_executable(unit_runtime tests/unit/runtime_test.cpp tests/unit/locks_stub.cpp
        dynamic-engine/src/preload/blocks.cpp
        dynamic-engine/src/preload/guard.cpp
        dynamic-engine/src/preload/heap.cpp
        dynamic-engine/src/preload/report.cpp
        dynamic-engine/src/preload/resources.cpp
        dynamic-engine/src/preload/rt.cpp
        dynamic-engine/src/preload/stacks.cpp
        dynamic-engine/src/preload/threads.cpp)
    target_include_directories(unit_runtime PRIVATE dynamic-engine/src/preload shared/include)
    target_compile_options(unit_runtime PRIVATE -fno-omit-frame-pointer)
    target_link_libraries(unit_runtime PRIVATE leakcheck_core Threads::Threads ${CMAKE_DL_LIBS})
    endif()

    set(units unit_static unit_scan unit_ai unit_reporter)
    if(NOT WIN32 AND NOT APPLE)
        list(APPEND units unit_runtime)
    endif()
    foreach(unit ${units})
        target_compile_options(${unit} PRIVATE -Wall -Wextra -g)
        add_test(NAME ${unit} COMMAND ${unit})
    endforeach()

    if(Python3_Interpreter_FOUND)
        if(WIN32)
            set(suites cli static scan windows)
        elseif(APPLE)
            set(suites static scan cli)
        else()
            set(suites cli dynamic static scan)
        endif()
        foreach(suite ${suites})
            add_test(NAME ${suite}
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/run_tests.py
                        --build ${CMAKE_BINARY_DIR} --source ${CMAKE_SOURCE_DIR} --suite ${suite})
        endforeach()
    endif()
endif()

# cmake --install. The preload library goes beside the binary because that is
# where the binary looks for it; the model goes where the compiled-in path and
# a relocated tree (bin/../share) both find it.
install(TARGETS leakcheck RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS leakcheck_preload
    LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY model/ DESTINATION ${CMAKE_INSTALL_DATADIR}/leakcheck/model
    FILES_MATCHING PATTERN "*.ai" PATTERN "*.json")
install(FILES docs/leakcheck.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES LICENSE README.md docs/REFERENCE.md docs/MODEL.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR})
