//
// Created by sams on 18/06/2023.
//
#include <stddef.h>
#ifndef UNTITLED11_BASE64_H
#define UNTITLED11_BASE64_H
void base64_cleanup();
char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length);
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length);

#endif //UNTITLED11_BASE64_H
