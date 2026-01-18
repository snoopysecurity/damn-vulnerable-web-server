#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include "authentication.h"
#include "mime_type_handler.h"
#include "request_logger.h"
#define MAX_REQUEST_SIZE 1024
#include "utils.h"
#include "error_handling.h"
#include "session_manager.h"

char SERVER_DIR[200];

// Renamed from send_authentication_required_response to reflect what it actually does
void serve_file(int client_socket, const char* file_path, const char* request, const std::string& set_cookie_header = "") {
    std::string response_header;

    FILE* file = fopen(file_path, "r");  // path traversal logic preserved

    if (file == nullptr) {
        perror("Failed to open file");
        response_header = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile Not Found";
        send_error_response(client_socket, 404, "Not Found", file_path);
        log_request_response(request, response_header);
        return;
    }

    if (check_php_file(file_path)) {
        response_header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
        if (!set_cookie_header.empty()) response_header += set_cookie_header;
        response_header += "\r\n";

        log_request_response(request, response_header);
        handle_php_file(file, &client_socket, response_header.c_str());
        fclose(file);
        return;
    }

    const char* content_type = get_content_type(file_path);
    char header_buf[512];
    snprintf(header_buf, sizeof(header_buf),
             "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n%s\r\n",
             content_type,
             set_cookie_header.empty() ? "" : set_cookie_header.c_str());

    response_header = header_buf;
    log_request_response(request, response_header);

    if (send(client_socket, response_header.c_str(), response_header.length(), 0) < 0) {
        perror("Failed to send response header");
        fclose(file);
        return;
    }

    char file_buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
        if (send(client_socket, file_buffer, bytes_read, 0) < 0) {
            perror("Failed to send file");
            break;
        }
    }

    fclose(file);
}

void handle_request(int client_socket, const char* request) {
    char* request_copy = strdup(request);
    char* path_start = strstr(request_copy, "GET /");
    if (path_start == nullptr) {
        perror("Invalid request");
        close(client_socket);
        free(request_copy);
        return;
    }

    char* path_end = strstr(path_start, " HTTP/");
    if (path_end == nullptr) {
        perror("Invalid request");
        close(client_socket);
        free(request_copy);
        return;
    }

    *path_end = '\0';
    char* path_with_query = path_start + 5;

    // Buffer Overflow Vulnerability Preserved
    char clean_path[200];
    strcpy(clean_path, path_with_query);

    char* query = strchr(clean_path, '?');
    if (query) {
        *query = '\0';
    }

    // 🚨 Special path for viewing logs
    if (strcmp(clean_path, "logs") == 0) {
        handle_log_viewer(client_socket, request);
        close(client_socket);
        free(request_copy);
        return;
    }

    if (clean_path[0] != '/') {
        char temp_path[200];
        sprintf(temp_path, "/%s", clean_path);  // Add a leading slash
        strcpy(clean_path, temp_path); // Update clean_path with leading slash
    }

    std::cout << "Request Path: " << clean_path << std::endl;

    bool authenticated = false;

    // Check if the path starts with "/admin"
    if (strncmp(clean_path, "/admin/", 7) == 0) {
        std::string authorization_header = extract_header_value(request, "Authorization:");
        if (authorization_header.empty()) {
            send_basic_auth_prompt(client_socket);
            close(client_socket);
            free(request_copy);
            return;
        }

        std::string username;
        std::string password;

        if (!extract_username_password(authorization_header, username, password)) {
            send_basic_auth_prompt(client_socket);
            close(client_socket);
            free(request_copy);
            return;
        }

        if (authenticate(username, password)) {
            authenticated = true;

             // Route for logger config
            if (strcmp(clean_path, "/admin/logger_config") == 0) {
                handle_logger_config(client_socket, request);
                close(client_socket);
                free(request_copy);
                return;
            }
        } else {
            send_basic_auth_prompt(client_socket);
            close(client_socket);
            free(request_copy);
            return;
        }
    }

    // Unified file serving logic
    char file_path[200];
    strcpy(file_path, SERVER_DIR);
    strcat(file_path, clean_path); // Path Traversal Vulnerability Preserved

    // Session Fixation Vulnerability Preserved
    std::string session_id = get_session_id_from_cookie(request);
    std::string set_cookie_header = "";
    if (session_id.empty()) {
        session_id = generate_session_id();
        set_cookie_header = "Set-Cookie: session_id=" + session_id + "; HttpOnly; Path=/\r\n";
        sessions[session_id] = "default_user_data";
    }
    
    // Serve the file
    serve_file(client_socket, file_path, request, set_cookie_header);
    
    close(client_socket);
    free(request_copy);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " SERVER_DIR PORT" << std::endl;
        std::cout << "Please specify server directory and port number" << std::endl;
        return 1;
    }

    strcpy(SERVER_DIR, argv[1]);  // buffer overflow
    int port = atoi(argv[2]);

    int server_socket, client_socket;
    struct sockaddr_in server_address{}, client_address{};
    socklen_t client_address_len = sizeof(client_address);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Failed to set SO_REUSEADDR");
        // Continue anyway, not critical
    }

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Failed to bind socket");
        return 1;
    }

    if (listen(server_socket, 10) < 0) {
        perror("Failed to listen for connections");
        return 1;
    }

    std::cout << "Server started on port " << port << std::endl;

    while (true) {
        // std::cout << "Waiting for request..." << std::endl;
        client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_address_len);
        if (client_socket < 0) {
            perror("Failed to accept connection");
            continue;
        }

        char request[MAX_REQUEST_SIZE];
        memset(request, 0, sizeof(request));

        int recv_result = recv(client_socket, request, sizeof(request), 0);
        if (recv_result == 0) {
            // std::cout << "Client closed the connection." << std::endl;
            close(client_socket);
            continue;
        } else if (recv_result < 0) {
            perror("Failed to receive request");
            close(client_socket);
            continue;
        }

        handle_request(client_socket, request);
    }

    close(server_socket);
    return 0;
}
