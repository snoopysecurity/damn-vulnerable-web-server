// http/request.h
//
// Thin wrapper around the raw HTTP request buffer. The intentional
// stack-BOF vulnerability lives inside HttpRequest::parse() (strcpy into
// a 200-byte clean_path buffer) and is preserved verbatim.
#ifndef DVWS_HTTP_REQUEST_H
#define DVWS_HTTP_REQUEST_H

#include <string>

struct HttpRequest {
    // The raw request bytes as received on the socket. Not owned.
    const char* raw = nullptr;

    // Method as parsed from the request line.
    std::string method;

    // The 200-byte fixed buffer written to via unbounded strcpy.
    // Intentional buffer-overflow primitive; do not change the size.
    char clean_path[200] = {0};

    // Everything after '?' in the request line, if any.
    std::string query;

    // Returns false if the request line could not be parsed at all.
    // On success, method/clean_path/query are populated and the
    // strcpy-based BOF has already had its chance to fire.
    // On failure, method holds the request-line token when the line was
    // well-formed but the method is unsupported (caller answers 405),
    // or "" when the line is malformed (caller answers 400).
    static bool parse(const char* raw_request, HttpRequest& out);

    // Convenience helpers that just re-run the utility parsers over `raw`.
    std::string header(const std::string& name) const;
};

#endif
