#ifndef MIME_TYPE_HANDLER_H
#define MIME_TYPE_HANDLER_H

#include <cstdio>   // for FILE
#include <cstdbool> // for bool in C++

#ifdef __cplusplus
extern "C" {
#endif

const char* get_content_type(const char* file_path);
bool check_php_file(const char* file_path);
// send_body: 0 for HEAD requests (interpreter still runs, output is
// drained but not sent), 1 otherwise.
void handle_php_file(FILE* file, int* client_socket, const char* response_header, int send_body);

#ifdef __cplusplus
}
#endif

#endif // MIME_TYPE_HANDLER_H
