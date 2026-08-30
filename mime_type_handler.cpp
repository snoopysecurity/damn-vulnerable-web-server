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
    // nginx-flavoured mapping table (REALISM_PLAN T7). Text types carry an
    // explicit charset; unknown extensions fall back to a binary stream
    // like a real server's default_type, not text/plain.
    static const struct {
        const char* ext;
        const char* type;
    } kTypes[] = {
        {".html", "text/html; charset=utf-8"},
        {".htm",  "text/html; charset=utf-8"},
        {".css",  "text/css; charset=utf-8"},
        {".js",   "application/javascript; charset=utf-8"},
        {".mjs",  "application/javascript; charset=utf-8"},
        {".json", "application/json; charset=utf-8"},
        {".txt",  "text/plain; charset=utf-8"},
        {".csv",  "text/csv; charset=utf-8"},
        {".md",   "text/plain; charset=utf-8"},
        {".xml",  "application/xml; charset=utf-8"},
        {".svg",  "image/svg+xml"},
        {".ico",  "image/x-icon"},
        {".png",  "image/png"},
        {".gif",  "image/gif"},
        {".jpeg", "image/jpeg"},
        {".jpg",  "image/jpeg"},
        {".webp", "image/webp"},
        {".pdf",  "application/pdf"},
        {".zip",  "application/zip"},
        {".gz",   "application/gzip"},
        {".tar",  "application/x-tar"},
        {".mp4",  "video/mp4"},
        {".woff", "font/woff"},
        {".woff2","font/woff2"},
    };

    const char* extension = strrchr(file_path, '.');
    if (extension != nullptr) {
        for (const auto& entry : kTypes) {
            if (strcmp(extension, entry.ext) == 0) {
                return entry.type;
            }
        }
    }
    return "application/octet-stream";
}

bool check_php_file(const char* file_path) {
    const char* extension = strrchr(file_path, '.');
    return (extension != nullptr && strcmp(extension, ".php") == 0);
}

void handle_php_file(FILE* file, int* client_socket, const char* response_header, int send_body) {
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
        if (send_body) {
            if (send(*client_socket, php_buffer, php_bytes_read, DVWS_SEND_FLAGS) < 0) {
                perror("Failed to send PHP output");
                return;
            }
        }
        // HEAD: drain interpreter output so pclose() sees a clean EOF.
    }

    fclose(file);
    remove(temp_file_path);
}
