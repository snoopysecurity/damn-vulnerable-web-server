// error_handling.h

#ifndef ERROR_HANDLING_H
#define ERROR_HANDLING_H

#ifdef __cplusplus
extern "C" {
#endif

// send_body: 0 for HEAD requests (headers only), 1 otherwise.
void send_error_response(int client_socket, int status_code, const char* status_text, const char* requested_page, int send_body);

#ifdef __cplusplus
}
#endif

#endif // ERROR_HANDLING_H
