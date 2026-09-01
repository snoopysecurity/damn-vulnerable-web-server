// mime_type_handler.cpp

#include "mime_type_handler.h"
#include "utils.h"
#include "net_compat.h"
#include "http/response.h"
#include "request_logger.h"
#include "server_config.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

const char* get_content_type(const char* file_path) {
    // nginx-flavoured mapping table. Text types carry an explicit
    // charset; unknown extensions fall back to a binary stream, not
    // text/plain.
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

void handle_cgi_helper(int client_socket, const char* request, int send_body) {
    // CH-06: every /cgi-helper request stages a copy of the bundled
    // dvws_cgi_helper executable at a predictable /tmp path, closes it,
    // waits, then executes it. The whole sequence is the intentional
    // CWE-377/CWE-367 temp-file race -- do not "fix" it.

    // Resolve the bundled helper first; without it there is nothing to
    // stage and the route answers 500 instead.
    const char* helper_path = get_cgi_helper_path();
    FILE* helper_file = nullptr;
    if (helper_path != nullptr) {
        helper_file = fopen(helper_path, "rb");
    }
    if (helper_file == nullptr) {
        std::string body = http::error_page(
            500, "Internal Server Error",
            "The bundled CGI helper executable could not be located.");
        http::send_status(client_socket, "500 Internal Server Error",
                          "text/html; charset=utf-8", body, "", send_body == 0);
        log_request_response(request, "HTTP/1.1 500 Internal Server Error");
        return;
    }

    pid_t pid = getpid();

    // Predictable staging path: /tmp, filename derived from the PID.
    // No O_EXCL, no private directory -- deliberately replaceable.
    char temp_file_path[200];
    snprintf(temp_file_path, sizeof(temp_file_path), "/tmp/dvws_cgi_%d", pid);

    FILE* temp_file = fopen(temp_file_path, "wb");
    if (temp_file == nullptr) {
        perror("Failed to create temporary file");
        fclose(helper_file);
        return;
    }

    // Stage a copy of the bundled helper executable.
    char file_buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), helper_file)) > 0) {
        fwrite(file_buffer, 1, bytes_read, temp_file);
    }
    fclose(helper_file);

    // The staged copy is closed here and only executed further below:
    // close-before-execute, the classic TOCTOU shape.
    fclose(temp_file);

    // Intentional race window. The old PHP bridge paid ~100 ms of
    // interpreter startup between staging and execution; the native
    // helper is too fast, so the gap is explicit. Anyone who can write
    // to /tmp can replace the staged executable during this window.
    // (Skipped in --fuzz mode only so the fuzzer's throughput does not
    // collapse; the staging itself still runs there.)
    if (!g_config.fuzz_mode) {
        usleep(100000);
    }

    chmod(temp_file_path, 0755);

    // Intentionally execute the predictable temporary file as the
    // server user. (No shell metacharacters can appear in the path: it
    // is "/tmp/dvws_cgi_" plus digits.)
    FILE* helper_output = popen(temp_file_path, "r");
    if (helper_output == nullptr) {
        perror("Failed to execute CGI helper");
        remove(temp_file_path);
        return;
    }

    // CGI-style response: no Content-Length; the connection close
    // delimits the body (standard behaviour for piped helper output).
    // The helper's own CGI header block is streamed verbatim as the
    // first body bytes.
    std::string response_header = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n";
    response_header += std::string("Server: ") + http::kServerBanner + "\r\n";
    response_header += "Date: " + http::http_date_now() + "\r\n";
    response_header += "Connection: close\r\n";
    response_header += "\r\n";

    log_request_response(request, response_header);

    if (send(client_socket, response_header.c_str(), response_header.length(), DVWS_SEND_FLAGS) < 0) {
        perror("Failed to send response header");
        pclose(helper_output);
        remove(temp_file_path);
        return;
    }

    char helper_buffer[1024];
    size_t helper_bytes_read;
    while ((helper_bytes_read = fread(helper_buffer, 1, sizeof(helper_buffer), helper_output)) > 0) {
        if (send_body) {
            if (send(client_socket, helper_buffer, helper_bytes_read, DVWS_SEND_FLAGS) < 0) {
                perror("Failed to send CGI helper output");
                break;
            }
        }
        // HEAD: drain helper output so pclose() sees a clean EOF.
    }

    pclose(helper_output);
    remove(temp_file_path);
}
