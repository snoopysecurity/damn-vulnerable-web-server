#ifndef DVWS_AUTHENTICATION_H
#define DVWS_AUTHENTICATION_H

#include <map>
#include <string>

int authenticate(const std::string& username, const std::string& password);
void send_basic_auth_prompt(int client_socket);
#endif  // DVWS_AUTHENTICATION_H
