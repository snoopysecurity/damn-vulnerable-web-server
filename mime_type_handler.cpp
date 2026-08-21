// mime_type_handler.cpp

#include "mime_type_handler.h"
#include "utils.h"
#include "net_compat.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

const char* get_content_type(const char* file_path) {
    const char* content_type = "text/plain"; // Default content type
    const char* extension = strrchr(file_path, '.');
    if (extension != nullptr) {
        if (strcmp(extension, ".html") == 0) {
            content_type = "text/html";
        } else if (strcmp(extension, ".jpeg") == 0 || strcmp(extension, ".jpg") == 0) {
            content_type = "image/jpeg";
        } else if (strcmp(extension, ".png") == 0) {
            content_type = "image/png";
        } else if (strcmp(extension, ".gif") == 0) {
            content_type = "image/gif";
        } else if (strcmp(extension, ".txt") == 0) {
            content_type = "text/plain";
        } else if (strcmp(extension, ".css") == 0) {
            content_type = "text/css";
        } else if (strcmp(extension, ".js") == 0) {
            content_type = "application/javascript";
        } else if (strcmp(extension, ".json") == 0) {
            content_type = "application/json";
        } else if (strcmp(extension, ".xml") == 0) {
            content_type = "application/xml";
        } else if (strcmp(extension, ".pdf") == 0) {
            content_type = "application/pdf";
        } else if (strcmp(extension, ".zip") == 0) {
            content_type = "application/zip";
        }
    }
    return content_type;
}

bool check_php_file(const char* file_path) {
    const char* extension = strrchr(file_path, '.');
    return (extension != nullptr && strcmp(extension, ".php") == 0);
}

void handle_php_file(FILE* file, int* client_socket, const char* response_header) {
    pid_t pid = getpid();

    char temp_file_path[200];
    snprintf(temp_file_path, sizeof(temp_file_path), "/tmp/php_script_%d.php", pid);

    FILE* temp_file = fopen(temp_file_path, "w");
    if (temp_file == nullptr) {
        perror("Failed to create temporary file");
        return;
    }

    char file_buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
        fwrite(file_buffer, 1, bytes_read, temp_file);
    }
    fclose(temp_file);

    const char* interpreter_path = get_php_interpreter_path();

    char command[256];
    snprintf(command, sizeof(command), "%s %s", interpreter_path, temp_file_path);

    FILE* php_output = popen(command, "r");
    if (php_output == nullptr) {
        perror("Failed to execute PHP script");
        return;
    }

    if (send(*client_socket, response_header, strlen(response_header), DVWS_SEND_FLAGS) < 0) {
        perror("Failed to send response header");
        fclose(file);
        return;
    }

    char php_buffer[1024];
    size_t php_bytes_read;
    while ((php_bytes_read = fread(php_buffer, 1, sizeof(php_buffer), php_output)) > 0) {
        if (send(*client_socket, php_buffer, php_bytes_read, DVWS_SEND_FLAGS) < 0) {
            perror("Failed to send PHP output");
            return;
        }
    }

    fclose(file);
    remove(temp_file_path);
}
