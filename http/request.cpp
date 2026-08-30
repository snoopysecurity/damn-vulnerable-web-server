// http/request.cpp
#include "request.h"
#include "../utils.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

// Classify a request line that GET/POST/HEAD parsing could not route, so
// dispatch() can answer like a real server instead of dropping the
// connection:
//   - "TOKEN SP target SP HTTP/x.y" with an unsupported method -> the
//     token is returned and the caller answers 405.
//   - anything else -> "" is returned and the caller answers 400.
std::string extract_method_token(const char* raw) {
    const char* eol = strstr(raw, "\r\n");
    size_t line_len = (eol != nullptr) ? (size_t)(eol - raw) : strlen(raw);
    std::string line(raw, line_len);

    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos || sp1 == 0) return "";
    size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return "";
    if (line.compare(sp2 + 1, 5, "HTTP/") != 0) return "";
    if (line.size() <= sp2 + 6) return "";  // need >= 1 version digit
    return line.substr(0, sp1);
}

}  // namespace

bool HttpRequest::parse(const char* raw_request, HttpRequest& out) {
    if (raw_request == nullptr) return false;
    out.raw = raw_request;

    char* request_copy = strdup(raw_request);
    int method_offset = 0;
    char* path_start = strstr(request_copy, "GET /");
    if (path_start != nullptr) {
        out.method = "GET";
        method_offset = 5;
    } else {
        path_start = strstr(request_copy, "POST /");
        if (path_start != nullptr) {
            out.method = "POST";
            method_offset = 6;
        } else {
            // HEAD is served exactly like GET minus the response body.
            // "HEAD /" shares GET's +5 path offset.
            path_start = strstr(request_copy, "HEAD /");
            if (path_start != nullptr) {
                out.method = "HEAD";
                method_offset = 5;
            }
        }
    }

    if (path_start == nullptr) {
        // Not GET/POST/HEAD. Record whether the request line was at least
        // well-formed so dispatch() can answer 405 vs 400 (it never just
        // drops the connection). out.method == "" means malformed.
        out.method = extract_method_token(request_copy);
        free(request_copy);
        return false;
    }

    char* path_end = strstr(path_start, " HTTP/");
    if (path_end == nullptr) {
        // No HTTP version on the request line: classify for 400/405 the
        // same way as unknown methods (out.method was tentatively set by
        // the method sniffing above and is not trustworthy here).
        out.method = extract_method_token(request_copy);
        free(request_copy);
        return false;
    }

    *path_end = '\0';
    char* path_with_query = path_start + method_offset;

    // Copy the raw path, unbounded, into the 200-byte clean_path.
    strcpy(out.clean_path, path_with_query);

    // Split off the query string component for handler convenience.
    char* qmark = strchr(out.clean_path, '?');
    if (qmark) {
        out.query = std::string(qmark + 1);
        *qmark = '\0';
    }

    // Normalize the path to start with '/'.
    if (out.clean_path[0] != '\0' && out.clean_path[0] != '/') {
        char temp_path[200];
        snprintf(temp_path, sizeof(temp_path), "/%s", out.clean_path);
        strcpy(out.clean_path, temp_path);
    }

    free(request_copy);
    return true;
}

std::string HttpRequest::header(const std::string& name) const {
    if (raw == nullptr) return "";
    return extract_header_value(raw, name + ":");
}
