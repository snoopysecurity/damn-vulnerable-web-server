// handlers/static_files.cpp
#include "static_files.h"

#include "../error_handling.h"
#include "../mime_type_handler.h"
#include "../net_compat.h"
#include "../request_logger.h"
#include "../server_config.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <sys/socket.h>

namespace handlers {

static void serve_file(int client_socket, const char* file_path,
                       const char* request,
                       const std::string& set_cookie_header) {
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

    if (send(client_socket, response_header.c_str(), response_header.length(), DVWS_SEND_FLAGS) < 0) {
        perror("Failed to send response header");
        fclose(file);
        return;
    }

    char file_buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
        if (send(client_socket, file_buffer, bytes_read, DVWS_SEND_FLAGS) < 0) {
            perror("Failed to send file");
            break;
        }
    }

    fclose(file);
}

void serve_static(int client_socket, const HttpRequest& req,
                  const std::string& set_cookie_header) {
    // --- INTENTIONAL VULNERABILITY (CWE-22, path traversal) ---
    char file_path[200];
    strcpy(file_path, g_config.server_dir);
    strcat(file_path, req.clean_path);

    serve_file(client_socket, file_path, req.raw, set_cookie_header);
}

}
