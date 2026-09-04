// http/request.h
//
// Thin wrapper around the raw HTTP request buffer. parse() copies the
// request path into the fixed-size clean_path buffer and splits off
// the query string.
#ifndef DVWS_HTTP_REQUEST_H
#define DVWS_HTTP_REQUEST_H

#include <string>

struct HttpRequest {
    // The raw request bytes as received on the socket. Not owned.
    const char* raw = nullptr;

    // Method as parsed from the request line.
    std::string method;

    // Fixed buffer the request path is copied into (unbounded strcpy
    // in parse()).
    char clean_path[200] = {0};

    // Everything after '?' in the request line, if any.
    std::string query;

    // Returns false if the request line could not be parsed at all.
    // On success, method/clean_path/query are populated.
    // On failure, method holds the request-line token when the line was
    // well-formed but the method is unsupported (caller answers 405),
    // or "" when the line is malformed (caller answers 400).
    static bool parse(const char* raw_request, HttpRequest& out);

    // Convenience helpers that just re-run the utility parsers over `raw`.
    std::string header(const std::string& name) const;
};

#endif
