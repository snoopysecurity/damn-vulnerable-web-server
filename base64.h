// base64.h

#ifndef BASE64_H
#define BASE64_H

#include <cstddef>

// Function to clean up decoding table
void base64_cleanup();

// Function to encode data to base64
char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length);

// Function to decode base64 encoded data
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length);

#endif  // BASE64_H
