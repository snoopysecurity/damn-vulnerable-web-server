// http/response.h
//
// Tiny helpers for the response side. Handlers that need a specific
// byte-for-byte response format should keep constructing their own
// strings; the helpers here are for the routine "send this body with
// this status" cases.
#ifndef DVWS_HTTP_RESPONSE_H
#define DVWS_HTTP_RESPONSE_H

#include <ctime>
#include <string>

namespace http {

// Server identification banner, sent on every response. Kept in sync
// with /status and the site footer.
inline const char* const kServerBanner = "DVWS/1.0";

// RFC 7231 IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
std::string http_date(std::time_t t);
std::string http_date_now();

// Consistent styled page for 301/400/403/404/405 responses. `detail` is
// inline HTML; the 404/403 callers reflect the requested path in it,
// everything else passes static strings only.
std::string error_page(int status_code, const std::string& reason, const std::string& detail = "");

// Send a full response with the given status line and body. Every response
// carries Content-Type, Content-Length, Server, Date and Connection: close.
// head_only (HEAD requests) sends the headers but suppresses the body
// (Content-Length still reports what a GET would have returned).
void send_status(int client_socket,
                 const std::string& status_code,  // e.g. "200 OK"
                 const std::string& content_type, const std::string& body,
                 const std::string& extra_headers = "", bool head_only = false);

inline void send_ok(int client_socket, const std::string& body,
                    const std::string& extra_headers = "", bool head_only = false) {
    send_status(client_socket, "200 OK", "text/plain; charset=utf-8", body, extra_headers,
                head_only);
}

// API-style JSON response. Bodies are always static strings built by
// the caller -- no request data is reflected into them.
inline void send_json(int client_socket, const std::string& body,
                      const std::string& extra_headers = "", bool head_only = false) {
    send_status(client_socket, "200 OK", "application/json", body, extra_headers, head_only);
}

}  // namespace http

#endif
