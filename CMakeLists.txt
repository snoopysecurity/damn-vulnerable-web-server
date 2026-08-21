cmake_minimum_required(VERSION 3.25)
project(damn_vulnerable_web_server CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(damn_vulnerable_web_server
    main.cpp
    router.cpp
    thread_pool.cpp
    cgi_rules.cpp
    http/request.cpp
    http/response.cpp
    handlers/admin.cpp
    handlers/cgi.cpp
    handlers/static_files.cpp
    handlers/status.cpp
    mime_type_handler.cpp
    request_logger.cpp
    error_handling.cpp
    authentication.cpp
    base64.cpp
    utils.cpp
    session_manager.cpp
    response_handler.cpp
)

# ---------------------------------------------------------------------------
# Hardening / mitigation flags
#
# Two levels of granularity are supported:
#
#   1. ENABLE_HARDENING -- convenience umbrella. When ON, forces
#      ENABLE_STACK_CANARY, ENABLE_NX, and defaults ENABLE_RELRO=FULL
#      unless the user already set them. Equivalent to the old
#      "vulnerable / hardened" two-mode switch.
#
#   2. Individual toggles for CTF workshops that want to teach one
#      mitigation at a time: ENABLE_RELRO, ENABLE_STACK_CANARY,
#      ENABLE_NX, FORTIFY_SOURCE_LEVEL, ENABLE_DEBUG.
#
# ENABLE_ASLR is kept as a deprecated alias for ENABLE_HARDENING.
# ---------------------------------------------------------------------------
option(ENABLE_HARDENING     "Enable PIE + all core hardening flags"   OFF)
option(ENABLE_ASLR          "Deprecated alias for ENABLE_HARDENING"   OFF)
option(ENABLE_ASAN          "Enable Address Sanitizer"                OFF)
set   (ENABLE_RELRO         "OFF"    CACHE STRING "Enable RELRO: OFF, PARTIAL, FULL")
option(ENABLE_STACK_CANARY  "Enable Stack Canary"                     OFF)
option(ENABLE_NX            "Enable No-Execute (NX)"                  OFF)
set   (FORTIFY_SOURCE_LEVEL 0        CACHE STRING "_FORTIFY_SOURCE level (0-3)")
option(ENABLE_DEBUG         "Enable debug symbols"                    ON)

if(ENABLE_ASLR AND NOT ENABLE_HARDENING)
    message(WARNING "ENABLE_ASLR is deprecated; use ENABLE_HARDENING instead.")
    set(ENABLE_HARDENING ON)
endif()

# Umbrella: opt every granular flag in when ENABLE_HARDENING is set,
# unless the user has already picked a specific value.
if(ENABLE_HARDENING)
    set(ENABLE_STACK_CANARY ON)
    set(ENABLE_NX           ON)
    if(ENABLE_RELRO STREQUAL "OFF")
        set(ENABLE_RELRO "FULL")
    endif()
endif()

if(ENABLE_ASAN)
    message(STATUS "Address Sanitizer Enabled")
    target_compile_options(damn_vulnerable_web_server PRIVATE -fsanitize=address -g)
    target_link_options   (damn_vulnerable_web_server PRIVATE -fsanitize=address)
endif()

# --- PIE / ASLR-friendly link ------------------------------------------------
if(ENABLE_HARDENING)
    message(STATUS "Hardening: PIE Enabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -fPIE)
        target_link_options   (damn_vulnerable_web_server PRIVATE -pie)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options   (damn_vulnerable_web_server PRIVATE "-Wl,-pie")
    endif()
else()
    message(STATUS "Hardening: PIE Disabled (vulnerable build)")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -fno-pie)
        target_link_options   (damn_vulnerable_web_server PRIVATE -no-pie)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options   (damn_vulnerable_web_server PRIVATE "LINKER:-no_pie")
    endif()
endif()

# --- RELRO -------------------------------------------------------------------
if(ENABLE_RELRO STREQUAL "FULL")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(STATUS "Full RELRO")
        target_link_options(damn_vulnerable_web_server PRIVATE "-Wl,-z,relro" "-Wl,-z,now")
    else()
        message(WARNING "RELRO is not supported on this OS")
    endif()
elseif(ENABLE_RELRO STREQUAL "PARTIAL")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(STATUS "Partial RELRO")
        target_link_options(damn_vulnerable_web_server PRIVATE "-Wl,-z,relro")
    else()
        message(WARNING "RELRO is not supported on this OS")
    endif()
elseif(ENABLE_RELRO STREQUAL "OFF")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(STATUS "RELRO Disabled")
        target_link_options(damn_vulnerable_web_server PRIVATE "-Wl,-z,norelro")
    endif()
else()
    message(FATAL_ERROR "Unknown RELRO variant: ${ENABLE_RELRO}. Use OFF, PARTIAL, or FULL.")
endif()

# --- Stack Canary ------------------------------------------------------------
if(ENABLE_STACK_CANARY)
    message(STATUS "Stack Canary Enabled")
    target_compile_options(damn_vulnerable_web_server PRIVATE -fstack-protector-strong)
else()
    message(STATUS "Stack Canary Disabled")
    target_compile_options(damn_vulnerable_web_server PRIVATE -fno-stack-protector)
endif()

# --- NX / execstack ----------------------------------------------------------
if(ENABLE_NX)
    message(STATUS "NX Enabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(damn_vulnerable_web_server PRIVATE -z noexecstack)
    endif()  # macOS forces NX by default.
else()
    message(STATUS "NX Disabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(damn_vulnerable_web_server PRIVATE -z execstack)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(damn_vulnerable_web_server PRIVATE -Wl,-allow_stack_execute)
    endif()
endif()

# --- Fortify Source ----------------------------------------------------------
message(STATUS "Fortify Source Level: ${FORTIFY_SOURCE_LEVEL}")
target_compile_options(damn_vulnerable_web_server PRIVATE "-D_FORTIFY_SOURCE=${FORTIFY_SOURCE_LEVEL}")
if(FORTIFY_SOURCE_LEVEL GREATER 0)
    target_compile_options(damn_vulnerable_web_server PRIVATE -O1)
else()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -Og)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_options(damn_vulnerable_web_server PRIVATE -O0)
    endif()
endif()

# --- Debug symbols -----------------------------------------------------------
if(ENABLE_DEBUG)
    message(STATUS "Debug symbols enabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -ggdb3)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_options(damn_vulnerable_web_server PRIVATE -g3)
    endif()
else()
    message(STATUS "Debug symbols disabled")
endif()

target_include_directories(damn_vulnerable_web_server PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Turn -Wall -Wextra on globally so accidental bugs are surfaced. The
# files below intentionally contain textbook antipatterns; silence the
# specific warning classes they trigger so CI logs stay useful.
target_compile_options(damn_vulnerable_web_server PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

set_source_files_properties(request_logger.cpp PROPERTIES
    COMPILE_FLAGS "-Wno-format-security -Wno-format-nonliteral"
)

set_source_files_properties(http/request.cpp PROPERTIES
    COMPILE_FLAGS "-Wno-deprecated-declarations"
)

set_source_files_properties(main.cpp PROPERTIES
    COMPILE_FLAGS "-Wno-deprecated-declarations"
)

set_source_files_properties(handlers/static_files.cpp PROPERTIES
    COMPILE_FLAGS "-Wno-deprecated-declarations"
)

set_source_files_properties(utils.cpp PROPERTIES
    COMPILE_FLAGS "-Wno-deprecated-declarations"
)

# Third-party-shaped base64 helper; keep as-is.
set_source_files_properties(base64.cpp PROPERTIES
    COMPILE_FLAGS "-Wno-sign-compare"
)

target_link_libraries(damn_vulnerable_web_server PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# ---------------------------------------------------------------------------
# libFuzzer harnesses (optional)
#
#     cmake -B build-fuzz -DENABLE_LIBFUZZER=ON \
#           -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
#     cmake --build build-fuzz --target fuzz_dispatch fuzz_query_params
#
# ---------------------------------------------------------------------------
option(ENABLE_LIBFUZZER "Build libFuzzer harnesses" OFF)

if(ENABLE_LIBFUZZER)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "ENABLE_LIBFUZZER requires clang / clang++")
    endif()

    set(FUZZ_COMMON_SOURCES
        router.cpp
        cgi_rules.cpp
        http/request.cpp
        http/response.cpp
        handlers/admin.cpp
        handlers/cgi.cpp
        handlers/static_files.cpp
        handlers/status.cpp
        mime_type_handler.cpp
        request_logger.cpp
        error_handling.cpp
        authentication.cpp
        base64.cpp
        utils.cpp
        session_manager.cpp
        response_handler.cpp
    )

    add_executable(fuzz_dispatch
        fuzz/harnesses/fuzz_dispatch.cpp
        ${FUZZ_COMMON_SOURCES}
    )
    target_compile_options(fuzz_dispatch PRIVATE
        -fsanitize=fuzzer,address,undefined -g -O1
    )
    target_link_options(fuzz_dispatch PRIVATE -fsanitize=fuzzer,address,undefined)
    target_include_directories(fuzz_dispatch PRIVATE
        ${OPENSSL_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(fuzz_dispatch PRIVATE OpenSSL::SSL OpenSSL::Crypto)

    add_executable(fuzz_query_params
        fuzz/harnesses/fuzz_query_params.cpp
        utils.cpp
        base64.cpp
    )
    target_compile_options(fuzz_query_params PRIVATE
        -fsanitize=fuzzer,address,undefined -g -O1
    )
    target_link_options(fuzz_query_params PRIVATE -fsanitize=fuzzer,address,undefined)
    target_include_directories(fuzz_query_params PRIVATE
        ${OPENSSL_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(fuzz_query_params PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
