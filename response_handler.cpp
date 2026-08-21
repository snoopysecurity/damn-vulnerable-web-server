// response_handler.cpp
#include <iostream>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include "net_compat.h"

// Function to send a generic HTTP response
void send_response(int client_socket, const std::string& status_code, 
                   const std::string& content_type, const std::string& body, const std::string& cookie = "") {
    std::string response_header = "HTTP/1.1 " + status_code + "\r\n";
    response_header += "Content-Type: " + content_type + "\r\n";
    if (!cookie.empty()) {
        response_header += cookie;  // Add the cookie if provided
    }
    response_header += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    response_header += "\r\n";  // End of headers

    // Send the header and body
    send(client_socket, response_header.c_str(), response_header.length(), DVWS_SEND_FLAGS);
    send(client_socket, body.c_str(), body.length(), DVWS_SEND_FLAGS);
}

// Function to send a 200 OK response
void send_200_response(int client_socket, const std::string& content, const std::string& cookie = "") {
    send_response(client_socket, "200 OK", "text/html", content, cookie);
}

// Function to send a 404 Not Found response
void send_404_response(int client_socket) {
    std::string body = "File Not Found";
    send_response(client_socket, "404 Not Found", "text/plain", body);
}
