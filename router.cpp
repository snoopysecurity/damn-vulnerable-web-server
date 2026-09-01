// router.cpp
//
// The dispatch() entry point: parses the request, routes it to the
// matching handler module, and closes the client socket.
#include "router.h"

#include "authentication.h"
#include "handlers/admin.h"
#include "handlers/cgi.h"
#include "handlers/echo.h"
#include "handlers/static_files.h"
#include "handlers/status.h"
#include "http/response.h"
#include "mime_type_handler.h"
#include "request_logger.h"
#include "server_config.h"
#include "session_manager.h"
#include "utils.h"

#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

ServerConfig g_config;

namespace {

struct AdminRoute {
    const char* path;
    void (*handler)(int, const HttpRequest&);
};

const AdminRoute kAdminRoutes[] = {
    {"/admin/system_status", handlers::system_status},
    {"/admin/upload_file", handlers::upload_file},
    {"/admin/add_rule", handlers::add_rule},
    {"/admin/update_rule", handlers::update_rule},
    {"/admin/logging", handlers::logging},
    {"/whoami", handlers::whoami},  // Basic-Auth protected
};

bool require_basic_auth(int client_socket, const HttpRequest& req) {
    std::string auth = req.header("Authorization");
    if (auth.empty()) {
        send_basic_auth_prompt(client_socket);
        return false;
    }
    std::string username, password;
    if (!extract_username_password(auth, username, password) || !authenticate(username, password)) {
        send_basic_auth_prompt(client_socket);
        return false;
    }
    return true;
}

}  // namespace

void dispatch(int client_socket, const char* raw_request) {
    HttpRequest req;
    if (!HttpRequest::parse(raw_request, req)) {
        // Answer instead of dropping the connection: a well-formed
        // request line with an unsupported method gets a 405 (+ Allow);
        // anything malformed gets a 400. Bodies are static strings: no
        // request data is reflected into the response.
        // Note: not a syscall failure, so perror() would print a bogus
        // errno string. Use fprintf on stderr instead.
        if (!req.method.empty()) {
            fprintf(stderr, "Unsupported method \"%s\"; answering 405.\n", req.method.c_str());
            http::send_status(
                client_socket, "405 Method Not Allowed", "text/html; charset=utf-8",
                http::error_page(405, "Method Not Allowed",
                                 "This server supports GET, POST and HEAD requests only."),
                "Allow: GET, POST, HEAD\r\n");
        } else {
            fprintf(stderr, "Malformed request line; answering 400.\n");
            http::send_status(
                client_socket, "400 Bad Request", "text/html; charset=utf-8",
                http::error_page(400, "Bad Request",
                                 "The request line could not be understood by the server."));
        }
        close(client_socket);
        return;
    }

    handlers::status_bump_request_counter();

    // Unauthenticated /status endpoint.
    if (strcmp(req.clean_path, "/status") == 0) {
        handlers::status(client_socket, req);
        close(client_socket);
        return;
    }

    // Log viewer; unauthenticated.
    if (strcmp(req.clean_path, "/logs") == 0) {
        handle_log_viewer(client_socket, req.raw);
        close(client_socket);
        return;
    }

    // Request echo / debug page; unauthenticated.
    if (strcmp(req.clean_path, "/echo") == 0) {
        handlers::echo_request(client_socket, req);
        close(client_socket);
        return;
    }

    // CH-06: bundled native CGI helper. Stages a copy of the helper
    // executable at a predictable /tmp path and executes it (the
    // insecure temp-file race lives in mime_type_handler.cpp).
    if (strcmp(req.clean_path, "/cgi-helper") == 0) {
        handle_cgi_helper(client_socket, req.raw, req.method == "HEAD" ? 0 : 1);
        close(client_socket);
        return;
    }

    std::cout << "Request Path: " << req.clean_path << std::endl;

    // Resolve session state once; the admin routes below also use it.
    std::string session_id = get_session_id_from_cookie(req.raw);
    std::string set_cookie_header;

    // Authenticated admin routes.
    if (strncmp(req.clean_path, "/admin/", 7) == 0 || strcmp(req.clean_path, "/whoami") == 0) {
        // /whoami works on the Basic credentials themselves, so it never
        // authenticates via the session.
        const bool whoami_route = (strcmp(req.clean_path, "/whoami") == 0);
        bool authorized = false;

        // An already-authenticated session is admitted directly;
        // otherwise fall back to Basic credentials.
        if (!whoami_route && !session_id.empty() &&
            get_session_data(session_id) == "authenticated:admin") {
            authorized = true;
        } else if (require_basic_auth(client_socket, req)) {
            authorized = true;
            if (!whoami_route && !session_id.empty()) {
                // Mark the existing session as authenticated.
                set_session_data(session_id, "authenticated:admin");
            }
        }

        if (!authorized) {
            close(client_socket);
            return;
        }

        for (const auto& route : kAdminRoutes) {
            if (strcmp(req.clean_path, route.path) == 0) {
                route.handler(client_socket, req);
                close(client_socket);
                return;
            }
        }
        // Authenticated but no admin sub-route matched -> fall through to
        // static file serving below (preserves original semantics).
    }

    // Type-confusion / CGI dispatch.
    if (handlers::cgi_dispatch(client_socket, req)) {
        close(client_socket);
        return;
    }

    // Fresh visitors get a minted session.
    if (session_id.empty()) {
        session_id = generate_session_id();
        set_cookie_header = "Set-Cookie: session_id=" + session_id + "; HttpOnly; Path=/\r\n";
        sessions[session_id] = "default_user_data";
    }

    handlers::serve_static(client_socket, req, set_cookie_header);
    close(client_socket);
}
