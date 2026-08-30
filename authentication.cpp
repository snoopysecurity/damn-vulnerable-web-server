//
// Created by sams on 11/06/2023.
//

#include <iostream>
#include <string>
#include <cstring>
#include <map>
#include <sstream>
#include <sys/socket.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <cctype>
#include "base64.h"
#include "authentication.h"
#include "http/response.h"
#include "utils.h"
#include "net_compat.h"

// Function to check if the provided username and password are valid
int authenticate(const std::string& username, const std::string& password) {
    if (username == "admin" && password == "admin") {
        return 1; // Successful login
    } else {
        return 0; // Login failed
    }
}

void send_basic_auth_prompt(int client_socket) {
    std::string header = "HTTP/1.1 401 Unauthorized\r\n";
    header += "WWW-Authenticate: Basic realm=\"Restricted\"\r\n";
    header += "Content-Length: 0\r\n";
    header += std::string("Server: ") + http::kServerBanner + "\r\n";
    header += "Date: " + http::http_date_now() + "\r\n";
    header += "Connection: close\r\n";
    header += "\r\n";

    if (send(client_socket, header.c_str(), header.length(), DVWS_SEND_FLAGS) < 0) {
        perror("Failed to send response header");
        return;
    }
}

