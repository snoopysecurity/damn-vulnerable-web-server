#ifndef MIME_TYPE_HANDLER_H
#define MIME_TYPE_HANDLER_H

#include <cstdio>   // for FILE
#include <cstdbool> // for bool in C++

#ifdef __cplusplus
extern "C" {
#endif

const char* get_content_type(const char* file_path);
// CH-06: stage the bundled dvws_cgi_helper executable at a predictable
// /tmp path and execute it (insecure temp-file race; see the .cpp).
// send_body: 0 for HEAD requests (helper still runs, output is
// drained but not sent), 1 otherwise.
void handle_cgi_helper(int client_socket, const char* request, int send_body);

#ifdef __cplusplus
}
#endif

#endif // MIME_TYPE_HANDLER_H
