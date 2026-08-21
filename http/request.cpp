// http/request.cpp
#include "request.h"
#include "../utils.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

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
        }
    }

    if (path_start == nullptr) {
        free(request_copy);
        return false;
    }

    char* path_end = strstr(path_start, " HTTP/");
    if (path_end == nullptr) {
        free(request_copy);
        return false;
    }

    *path_end = '\0';
    char* path_with_query = path_start + method_offset;

    // --- INTENTIONAL VULNERABILITY (CWE-121, stack BOF) ---
    // Unbounded strcpy into a 200-byte on-stack buffer.
    // Do not "fix" this: it is the primary teaching primitive.
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
