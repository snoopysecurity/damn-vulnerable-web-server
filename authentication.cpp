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
    const char* header = "HTTP/1.1 401 Unauthorized\r\n"
                         "WWW-Authenticate: Basic realm=\"Restricted\"\r\n"
                         "Content-Length: 0\r\n"
                         "Custom-Header: SomeValue\r\n"
                         "\r\n";

    if (send(client_socket, header, strlen(header), DVWS_SEND_FLAGS) < 0) {
        perror("Failed to send response header");
        return;
    }
}


// Function to perform authentication for a given file path
void handle_authentication(int client_socket, const std::string& username) {
    // 🚨 Type Confusion: Misinterpreting std::string as char*
    // Using const_cast to cast away const-ness and create a vulnerability
    char* leaked_ptr = const_cast<char*>(username.c_str());  // Type confusion

    const char* preamble = "Leaked internal username object bytes:\n";
    send(client_socket, preamble, strlen(preamble), DVWS_SEND_FLAGS);

    // Leak internal bytes of the std::string username object (misinterpreted as a char* pointer)
    send(client_socket, leaked_ptr, 64, DVWS_SEND_FLAGS);  // Potential data leakage (depending on implementation)

    // Further operations or handling after potential type confusion
    std::cout << "Extracted Username: " << username << std::endl;
    // Additional processing logic...
    const char* ok = "\nHTTP/1.1 200 OK\r\n\r\nWelcome!";
    send(client_socket, ok, strlen(ok), DVWS_SEND_FLAGS);
}

