cmake_minimum_required(VERSION 3.25)
project(untitled11 C)

set(CMAKE_C_STANDARD 11)

# Add OpenSSL flags and include directories
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Add your source files to the executable
add_executable(untitled11 main.c mime_type_handler.c mime_type_handler.h request_logger.c request_logger.h error_handling.c error_handling.h authentication.c authentication.h base64.c base64.h)

# Link OpenSSL libraries to the executable
target_link_libraries(untitled11 OpenSSL::SSL OpenSSL::Crypto)