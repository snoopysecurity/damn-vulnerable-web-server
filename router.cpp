// router.cpp
//
// Extracted from the former monolithic handle_request() in main.cpp.
// Structure only; every intentional vulnerability continues to live in
// its dedicated handler and behaves byte-for-byte identically.
#include "router.h"

#include "authentication.h"
#include "handlers/admin.h"
#include "handlers/cgi.h"
#include "handlers/static_files.h"
#include "handlers/status.h"
#include "http/response.h"
#include "request_logger.h"
#include "session_manager.h"
#include "utils.h"
#include "server_config.h"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <unistd.h>

ServerConfig g_config;

namespace {

struct AdminRoute {
    const char* path;
    void (*handler)(int, const HttpRequest&);
};

const AdminRoute kAdminRoutes[] = {
    {"/admin/system_status", handlers::system_status},
    {"/admin/upload_file",   handlers::upload_file},
    {"/admin/add_rule",      handlers::add_rule},
    {"/whoami",              handlers::whoami},  // basic-auth'd info-leak route
};

bool require_basic_auth(int client_socket, const HttpRequest& req) {
    std::string auth = req.header("Authorization");
    if (auth.empty()) {
        send_basic_auth_prompt(client_socket);
        return false;
    }
    std::string username, password;
    if (!extract_username_password(auth, username, password) ||
        !authenticate(username, password)) {
        send_basic_auth_prompt(client_socket);
        return false;
    }
    return true;
}

}  // namespace

void dispatch(int client_socket, const char* raw_request) {
    HttpRequest req;
    if (!HttpRequest::parse(raw_request, req)) {
        // Real servers answer; they don't drop the connection silently.
        // A well-formed request line with an unsupported method gets a
        // 405 (+ Allow); anything malformed gets a 400. Bodies are static
        // strings: no request data is reflected into the response.
        // Note: not a syscall failure, so perror() would print a bogus
        // errno string. Use fprintf on stderr instead.
        if (!req.method.empty()) {
            fprintf(stderr, "Unsupported method \"%s\"; answering 405.\n",
                    req.method.c_str());
            http::send_status(client_socket, "405 Method Not Allowed",
                              "text/html; charset=utf-8",
                              http::error_page(405, "Method Not Allowed",
                                               "This server supports GET, POST and HEAD requests only."),
                              "Allow: GET, POST, HEAD\r\n");
        } else {
            fprintf(stderr, "Malformed request line; answering 400.\n");
            http::send_status(client_socket, "400 Bad Request",
                              "text/html; charset=utf-8",
                              http::error_page(400, "Bad Request",
                                               "The request line could not be understood by the server."));
        }
        close(client_socket);
        return;
    }

    handlers::status_bump_request_counter();

    // Unauthenticated /status endpoint for workshop instructors.
    if (strcmp(req.clean_path, "/status") == 0) {
        handlers::status(client_socket, req);
        close(client_socket);
        return;
    }

    // Special: log viewer (unauthenticated by design; command injection sink).
    if (strcmp(req.clean_path, "/logs") == 0) {
        handle_log_viewer(client_socket, req.raw);
        close(client_socket);
        return;
    }

    std::cout << "Request Path: " << req.clean_path << std::endl;

    // Authenticated admin routes.
    if (strncmp(req.clean_path, "/admin/", 7) == 0 ||
        strcmp(req.clean_path, "/whoami") == 0) {
        if (!require_basic_auth(client_socket, req)) {
            close(client_socket);
            return;
        }

        if (strcmp(req.clean_path, "/admin/logger_config") == 0) {
            handle_logger_config(client_socket, req.raw);
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

    // Session fixation lives here: never rotates a client-supplied cookie.
    std::string session_id = get_session_id_from_cookie(req.raw);
    std::string set_cookie_header;
    if (session_id.empty()) {
        session_id = generate_session_id();
        set_cookie_header = "Set-Cookie: session_id=" + session_id + "; HttpOnly; Path=/\r\n";
        sessions[session_id] = "default_user_data";
    }

    handlers::serve_static(client_socket, req, set_cookie_header);
    close(client_socket);
}
