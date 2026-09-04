// response_handler.h
#ifndef RESPONSE_HANDLER_H
#define RESPONSE_HANDLER_H

#include <string>

// Sends a generic HTTP response with the given status code, content type, body, and optional cookie
void send_response(int client_socket, const std::string& status_code,
                   const std::string& content_type, const std::string& body,
                   const std::string& cookie = "");

// Sends a 200 OK HTTP response with the provided content and optional cookie
void send_200_response(int client_socket, const std::string& content,
                       const std::string& cookie = "");

// Sends a 404 Not Found HTTP response
void send_404_response(int client_socket);

#endif  // RESPONSE_HANDLER_H
