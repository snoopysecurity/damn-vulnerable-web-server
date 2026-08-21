// fuzz_query_params.cpp
//
// libFuzzer harness for extract_query_parameters(). This is a small,
// deterministic function that reads a raw HTTP request and returns a
// map of query parameters -- a great teaching example of structure-
// aware fuzzing on a pure parser (no side effects, no sockets).

#include <cstddef>
#include <cstdint>
#include <string>

#include "../../utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 8192) return 0;
    std::string s(reinterpret_cast<const char*>(data), size);
    (void)extract_query_parameters(s);
    return 0;
}
