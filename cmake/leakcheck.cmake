# leakcheck.cmake: one line in a CMake project adds a leakcheck target.
#
#   list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
#   include(leakcheck)
#   leakcheck_add_target(leakcheck)          # compile_commands.json, or the source dir
#   # or, with a baseline and a suppression file:
#   leakcheck_add_target(leakcheck_check
#       ARGS --baseline compare .leakcheck-baseline.txt -s ci/leakcheck.supp)
#
# The target uses the leakcheck this project builds (when there is one), else
# the one on PATH or in LEAKCHECK_EXECUTABLE. It fails the build on findings, so
# `cmake --build . --target leakcheck` is a gate, not just a report.

include_guard(GLOBAL)

if(TARGET leakcheck)
    set(_leakcheck_tool "$<TARGET_FILE:leakcheck>")
else()
    find_program(LEAKCHECK_EXECUTABLE NAMES leakcheck HINTS "${CMAKE_SOURCE_DIR}/build"
        "$ENV{HOME}/.local/bin" DOC "leakcheck binary used by leakcheck_add_target")
    if(NOT LEAKCHECK_EXECUTABLE)
        message(FATAL_ERROR
            "leakcheck_add_target: no leakcheck target in this build and none on PATH. "
            "Install a release, or add_subdirectory() the leakcheck source.")
    endif()
    set(_leakcheck_tool "${LEAKCHECK_EXECUTABLE}")
endif()

function(leakcheck_add_target name)
    cmake_parse_arguments(ARG "" "TARGET;FORMAT;OUTPUT" "ARGS" ${ARGN})
    if(NOT ARG_TARGET)
        # A compile database is what static analysis wants: it is the list of
        # translation units the build actually compiles. Without one, the
        # source tree is walked and the same rules apply.
        if(EXISTS "${CMAKE_BINARY_DIR}/compile_commands.json")
            set(ARG_TARGET "${CMAKE_BINARY_DIR}/compile_commands.json")
        else()
            set(ARG_TARGET "${CMAKE_CURRENT_SOURCE_DIR}")
        endif()
    endif()
    set(_args static ${ARG_ARGS})
    if(ARG_FORMAT)
        list(APPEND _args -f "${ARG_FORMAT}")
    endif()
    if(ARG_OUTPUT)
        list(APPEND _args -o "${ARG_OUTPUT}")
    endif()
    add_custom_target(${name}
        COMMAND ${_leakcheck_tool} ${_args} ${ARG_TARGET}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "leakcheck: ${ARG_TARGET}"
        USES_TERMINAL
        VERBATIM)
endfunction()
