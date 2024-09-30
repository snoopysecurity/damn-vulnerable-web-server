//
// Created by sams on 11/06/2023.
//

#ifndef UNTITLED11_AUTHENTICATION_H
#define UNTITLED11_AUTHENTICATION_H

int authenticate(const char* username, const char* password);
int perform_authentication(int client_socket, const char* file_path, const char* request);
void send_basic_auth_prompt(int client_socket);
const char* extract_header_value(const char* request, const char* header_name);
#endif //UNTITLED11_AUTHENTICATION_H
