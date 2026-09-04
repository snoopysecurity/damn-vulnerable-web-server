// fuzz_query_params.cpp
//
// libFuzzer harness for extract_query_parameters(): feeds the fuzzer
// bytes to the parser as a raw HTTP request (no side effects, no
// sockets).

#include <cstddef>
#include <cstdint>
#include <string>

#include "utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 8192) return 0;
    std::string s(reinterpret_cast<const char*>(data), size);
    (void)extract_query_parameters(s);
    return 0;
}
