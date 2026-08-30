// handlers/admin.cpp
//
// Home for the /admin/* routes. Each function contains one intentional
// vulnerability, kept byte-for-byte identical to the original main.cpp
// implementation so the exploit regression tests keep passing.
#include "admin.h"

#include "../authentication.h"
#include "../http/response.h"
#include "../utils.h"
#include "../cgi_rules.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace handlers {

void system_status(int client_socket, const HttpRequest& req) {
    const bool head_only = (req.method == "HEAD");
    const char* request = req.raw;
    const char* status_pos = strstr(request, "status=");
    if (!status_pos) {
        http::send_json(client_socket,
                        "{\"status\": \"error\", \"message\": \"Missing status parameter.\"}",
                        "", head_only);
        return;
    }
    status_pos += 7; // skip "status="

    // --- INTENTIONAL VULNERABILITY (CWE-122, heap BOF) ---
    // 32-byte allocation, unbounded copy from user input.
    char* status_msg = (char*)malloc(32);
    int i = 0;
    while (status_pos[i] != '\0' && status_pos[i] != '\n' && status_pos[i] != '\r') {
        status_msg[i] = status_pos[i]; // No bounds check!
        i++;
    }
    status_msg[i] = '\0';

    http::send_json(client_socket,
                    "{\"status\": \"ok\", \"message\": \"System status updated.\"}",
                    "", head_only);
    free(status_msg);
}

void upload_file(int client_socket, const HttpRequest& req) {
    const bool head_only = (req.method == "HEAD");
    std::string content_length_str = req.header("Content-Length");
    if (content_length_str.empty()) {
        http::send_json(client_socket,
                        "{\"status\": \"error\", \"message\": \"Missing Content-Length.\"}",
                        "", head_only);
        return;
    }

    // --- INTENTIONAL VULNERABILITY (CWE-190, integer overflow) ---
    unsigned int content_len = (unsigned int)strtoul(content_length_str.c_str(), nullptr, 10);
    unsigned int buffer_size = content_len + 64; // wraps if content_len near UINT_MAX
    char* file_buffer = (char*)malloc(buffer_size);
    if (file_buffer) {
        recv(client_socket, file_buffer, content_len, 0);
        http::send_json(client_socket,
                        "{\"status\": \"ok\", \"message\": \"Upload processed.\"}",
                        "", head_only);
        free(file_buffer);
    }
}

void add_rule(int client_socket, const HttpRequest& req) {
    auto params = extract_query_parameters(req.raw);
    std::string type = params["type"];
    std::string path = params["path"];
    std::string target = params["target"];

    if (type == "alias") {
        // --- INTENTIONAL VULNERABILITY (CWE-843, type-confusion setup) ---
        AliasRule* rule = new AliasRule();
        rule->path = path;
        strncpy(rule->target, target.c_str(), 63);
        cgi_rules().push_back(rule);
    } else if (type == "exec") {
        ExecRule* rule = new ExecRule();
        rule->path = path;
        rule->callback = default_cgi_handler;
        cgi_rules().push_back(rule);
    }

    http::send_json(client_socket,
                    "{\"status\": \"ok\", \"message\": \"Rule added.\", \"rules\": " +
                        std::to_string(cgi_rules().size()) + "}",
                    "", req.method == "HEAD");
}

void whoami(int client_socket, const HttpRequest& req) {
    // Extract the caller's username from the Basic Auth header again so we
    // can hand it to the intentionally-vulnerable info-leak sink.
    std::string auth = req.header("Authorization");
    std::string username, password;
    if (auth.empty() || !extract_username_password(auth, username, password)) {
        http::send_status(client_socket, "401 Unauthorized", "application/json",
                          "{\"status\": \"error\", \"message\": \"no credentials\"}",
                          "", req.method == "HEAD");
        return;
    }
    // handle_authentication() leaks 64 bytes past the std::string internals.
    handle_authentication(client_socket, username, req.method == "HEAD");
}

}
