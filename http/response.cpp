// http/response.cpp
#include "response.h"
#include "../net_compat.h"

#include <sys/socket.h>
#include <cstring>

namespace http {

void send_status(int client_socket,
                 const std::string& status_code,
                 const std::string& content_type,
                 const std::string& body,
                 const std::string& extra_headers) {
    std::string header = "HTTP/1.1 " + status_code + "\r\n";
    header += "Content-Type: " + content_type + "\r\n";
    if (!extra_headers.empty()) header += extra_headers;
    header += "\r\n";

    send(client_socket, header.c_str(), header.length(), DVWS_SEND_FLAGS);
    if (!body.empty()) {
        send(client_socket, body.c_str(), body.length(), DVWS_SEND_FLAGS);
    }
}

}
