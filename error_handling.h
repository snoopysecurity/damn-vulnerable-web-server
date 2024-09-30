//
// Created by sams on 10/06/2023.
//

#ifndef UNTITLED11_ERROR_HANDLING_H
#define UNTITLED11_ERROR_HANDLING_H
void send_error_response(int client_socket, int status_code, const char* status_text, const char* requested_page);
#endif //UNTITLED11_ERROR_HANDLING_H
