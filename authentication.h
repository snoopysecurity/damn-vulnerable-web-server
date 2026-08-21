#ifndef DVWS_AUTHENTICATION_H
#define DVWS_AUTHENTICATION_H

#include <string>
#include <map>


int authenticate(const std::string& username, const std::string& password);
void send_basic_auth_prompt(int client_socket);
void handle_authentication(int client_socket, const std::string& username);
#endif // DVWS_AUTHENTICATION_H
