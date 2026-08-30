// error_handling.cpp

#include <cstdio>  // for FILE, perror
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>  // for close
#include <iostream>  // for perror and error handling

#include "http/response.h"
#include "request_logger.h"
#include "error_handling.h"
#include "net_compat.h"
#include "server_config.h"

void send_error_response(int client_socket, int status_code, const char* status_text, const char* requested_page, int send_body) {
    // Styled, consistent error page (REALISM_PLAN T5). The reflection of
    // the requested path is intentional pre-existing behavior.
    std::string body = http::error_page(
        status_code, status_text,
        std::string("Requested page: ") + requested_page);

    // Full standard header set (REALISM_PLAN T4).
    std::string response_header = "HTTP/1.1 " + std::to_string(status_code) +
                                  " " + status_text + "\r\n";
    response_header += "Content-Type: text/html; charset=utf-8\r\n";
    response_header += "Content-Length: " + std::to_string(body.length()) + "\r\n";
    response_header += std::string("Server: ") + http::kServerBanner + "\r\n";
    response_header += "Date: " + http::http_date_now() + "\r\n";
    response_header += "Connection: close\r\n";
    response_header += "\r\n";

    // Send the response header
    if (send(client_socket, response_header.c_str(), response_header.length(), DVWS_SEND_FLAGS) < 0) {
        perror("Failed to send response header");
        return;
    }

    if (!send_body) return;  // HEAD: headers only

    // Send the error message
    if (send(client_socket, body.c_str(), body.length(), DVWS_SEND_FLAGS) < 0) {
        perror("Failed to send error message");
        return;
    }
}
