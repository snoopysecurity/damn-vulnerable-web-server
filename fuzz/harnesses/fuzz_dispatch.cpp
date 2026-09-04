// fuzz_dispatch.cpp
//
// libFuzzer harness for the top-level HTTP request dispatcher.
// Builds a NUL-terminated copy of the fuzzer-supplied byte buffer and
// hands it to dispatch(0, ...). Response send()s target fd 0, which is
// closed early by libFuzzer, so they fail harmlessly.
//
// Build:
//   clang++ -std=c++17 -O1 -g -fsanitize=fuzzer,address,undefined \
//       fuzz/harnesses/fuzz_dispatch.cpp \
//       main_lib_stub.cpp router.cpp cgi_rules.cpp \
//       http/request.cpp http/response.cpp \
//       handlers/*.cpp \
//       authentication.cpp base64.cpp utils.cpp \
//       session_manager.cpp response_handler.cpp \
//       request_logger.cpp error_handling.cpp mime_type_handler.cpp \
//       -lssl -lcrypto -o fuzz_dispatch
//
// See CMakePresets fuzz-libfuzzer for a one-liner.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "router.h"
#include "server_config.h"

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    // Sane defaults for the global config so path-traversal / static-file
    // paths do not immediately crash on an empty server_dir.
    strcpy(g_config.server_dir, "/tmp");
    g_config.port = 0;
    g_config.fuzz_mode = true;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Bound: 4 KiB is well above the 1 KiB the real server accepts and
    // still exercises path-length overflow behavior.
    if (size == 0 || size > 4096) return 0;

    char* buf = (char*)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    dispatch(0, buf);

    free(buf);
    return 0;
}
