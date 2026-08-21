cmake_minimum_required(VERSION 3.25)
project(damn_vulnerable_web_server CXX)

set(CMAKE_CXX_STANDARD 11)

# Add OpenSSL flags and include directories
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Add your source files to the executable
add_executable(damn_vulnerable_web_server
    main.cpp
    mime_type_handler.cpp
    request_logger.cpp
    error_handling.cpp
    authentication.cpp
    base64.cpp
    utils.cpp
    session_manager.cpp
    response_handler.cpp
)

option(ENABLE_ASLR "Enable Address Space Layout Randomization (ASLR)" OFF)
set(ENABLE_RELRO "OFF" CACHE STRING "Enable RELRO")
option(ENABLE_STACK_CANARY "Enable Stack Canary" OFF)
option(ENABLE_NX "Enable No-Execute (NX)" OFF)
set(FORTIFY_SOURCE_LEVEL 0 CACHE STRING "Fortify Source Level")
option(ENABLE_DEBUG "Enable debug symbols" ON)

option(ENABLE_ASAN "Enable Address Sanitizer" OFF)
if(ENABLE_ASAN)
    message(STATUS "Address Sanitizer Enabled")
    target_compile_options(damn_vulnerable_web_server PRIVATE -fsanitize=address -g)
    target_link_options(damn_vulnerable_web_server PRIVATE -fsanitize=address)
endif()

# Only apply flags after target is defined
if(ENABLE_ASLR)
    message(STATUS "ASLR Enabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -fPIE)
        target_link_options(damn_vulnerable_web_server PRIVATE -pie)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(damn_vulnerable_web_server PRIVATE "-Wl,-pie")
    endif()
else()
    message(STATUS "ASLR Disabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -fno-pie)
        target_link_options(damn_vulnerable_web_server PRIVATE -no-pie)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(damn_vulnerable_web_server PRIVATE "LINKER:-no_pie")
    endif()
endif()

if(ENABLE_RELRO STREQUAL "FULL")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(STATUS "Full RELRO")
        target_link_options(damn_vulnerable_web_server PRIVATE "-Wl,-z,relro" "-Wl,-z,now")
    else()
        message(WARNING "RELRO is not supported in your operating system")
    endif()
elseif(ENABLE_RELRO STREQUAL "PARTIAL")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(STATUS "Partial RELRO")
        target_link_options(damn_vulnerable_web_server PRIVATE "-Wl,-z,relro")
    else()
        message(WARNING "RELRO is not supported in your operating system")
    endif()
elseif(ENABLE_RELRO STREQUAL "OFF")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(STATUS "Disabled RELRO")
        target_link_options(damn_vulnerable_web_server PRIVATE "-Wl,-z,norelro")
    endif()
else()
    message(FATAL_ERROR "Unknown RELRO variant: ${ENABLE_RELRO}. Choose 'OFF', 'PARTIAL', or 'FULL'.")
endif()

if(ENABLE_STACK_CANARY)
    message(STATUS "Stack Canary Enabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -fstack-protector-strong)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_options(damn_vulnerable_web_server PRIVATE -fstack-protector-strong)
    endif()
else()
    message(STATUS "Stack Canary Disabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -fno-stack-protector)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_options(damn_vulnerable_web_server PRIVATE -fno-stack-protector)
    endif()
endif()

if(ENABLE_NX)
    message(STATUS "NX Enabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(damn_vulnerable_web_server PRIVATE -z noexecstack)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        #On OSX NX is forced by default
    endif()
else()
    message(STATUS "NX Disabled")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(damn_vulnerable_web_server PRIVATE -z execstack)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(damn_vulnerable_web_server PRIVATE -Wl,-allow_stack_execute)
    endif()
endif()

message(STATUS "Fortify Source Level: ${FORTIFY_SOURCE_LEVEL}")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_options(damn_vulnerable_web_server PRIVATE "-D_FORTIFY_SOURCE=${FORTIFY_SOURCE_LEVEL}")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_compile_options(damn_vulnerable_web_server PRIVATE "-D_FORTIFY_SOURCE=${FORTIFY_SOURCE_LEVEL}")
endif()

if(FORTIFY_SOURCE_LEVEL GREATER 0)
    target_compile_options(damn_vulnerable_web_server PRIVATE -O1)
else()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(damn_vulnerable_web_server PRIVATE -Og)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_options(damn_vulnerable_web_server PRIVATE -O0)
    endif()
endif()

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

target_include_directories(damn_vulnerable_web_server PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(damn_vulnerable_web_server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
