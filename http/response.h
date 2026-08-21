// http/response.h
//
// Tiny helpers for the response side. Handlers that need to preserve a
// specific byte-for-byte response format (because a challenge depends on
// it) should keep constructing their own strings; the helpers here are
// only for the routine "send this body with this status" cases.
#ifndef DVWS_HTTP_RESPONSE_H
#define DVWS_HTTP_RESPONSE_H

#include <string>

namespace http {

// Send a full response with the given status line and body.
void send_status(int client_socket,
                 const std::string& status_code,      // e.g. "200 OK"
                 const std::string& content_type,
                 const std::string& body,
                 const std::string& extra_headers = "");

inline void send_ok(int client_socket, const std::string& body,
                    const std::string& extra_headers = "") {
    send_status(client_socket, "200 OK", "text/plain", body, extra_headers);
}

}

#endif
