// base64.cpp

#include "base64.h"
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cstdint>

static const char encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static char *decoding_table = nullptr;
static const int mod_table[] = { 0, 2, 1 };

void build_decoding_table() {
    decoding_table = static_cast<char*>(std::malloc(256));
    if (!decoding_table) {
        std::cerr << "Failed to allocate memory for decoding table!" << std::endl;
        return;
    }

    std::memset(decoding_table, -1, 256);
    for (int i = 0; i < 64; i++) {
        decoding_table[static_cast<unsigned char>(encoding_table[i])] = i;
    }
}

void base64_cleanup() {
    std::free(decoding_table);
    decoding_table = nullptr;
}

char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = static_cast<char*>(std::malloc(*output_length));
    if (encoded_data == nullptr) {
        return nullptr;
    }

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? static_cast<unsigned char>(data[i++]) : 0;
        uint32_t octet_b = i < input_length ? static_cast<unsigned char>(data[i++]) : 0;
        uint32_t octet_c = i < input_length ? static_cast<unsigned char>(data[i++]) : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = encoding_table[triple & 0x3F];
    }

    for (size_t i = 0; i < mod_table[input_length % 3]; i++) {
        encoded_data[*output_length - 1 - i] = '=';
    }

    return encoded_data;
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {
    if (decoding_table == nullptr) {
        build_decoding_table();
    }

    if (input_length % 4 != 0) {
        return nullptr;
    }

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    // Allocate one extra byte so callers can safely NUL-terminate the
    // returned buffer (e.g. extract_username_password() writes '\0' at
    // [*output_length]). Without this, ASan trips a 1-byte heap-buffer-
    // overflow on every Basic-Auth request and takes the server down
    // before any of the intentional vulnerabilities can be exercised.
    unsigned char* decoded_data = static_cast<unsigned char*>(std::malloc(*output_length + 1));
    if (decoded_data == nullptr) {
        return nullptr;
    }

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[static_cast<unsigned char>(data[i++])];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[static_cast<unsigned char>(data[i++])];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[static_cast<unsigned char>(data[i++])];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[static_cast<unsigned char>(data[i++])];

        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < *output_length) decoded_data[j++] = (triple >> 16) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = triple & 0xFF;
    }

    return decoded_data;
}
