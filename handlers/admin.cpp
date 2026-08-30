// handlers/admin.cpp
//
// Handlers for the /admin/* routes (plus /whoami). Each handler parses
// what it needs from the request, writes the response, and returns;
// the router has already authenticated the client.
#include "admin.h"

#include "../authentication.h"
#include "../cgi_rules.h"
#include "../http/response.h"
#include "../logging_sink.h"
#include "../utils.h"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace handlers {

namespace {

int hex_val(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Decode a %-escaped parameter value into dst. Valid %XX escapes
// collapse to one byte; anything else -- including malformed escapes
// like "%GZ" or a truncated trailing '%' -- is copied verbatim. Stops
// at NUL, CR or LF (parameter terminator).
void decode_status_param(const char* src, char* dst) {
    size_t i = 0, o = 0;
    while (src[i] != '\0' && src[i] != '\n' && src[i] != '\r') {
        if (src[i] == '%') {
            int hi = hex_val((unsigned char)src[i + 1]);
            int lo = (hi >= 0) ? hex_val((unsigned char)src[i + 2]) : -1;
            if (hi >= 0 && lo >= 0) {
                dst[o++] = (char)((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        dst[o++] = src[i++];
    }
    dst[o] = '\0';
}

// Uploads are stored as a fixed 64-byte header followed by the body, so
// the backing store can index records without parsing them.
struct UploadHeader {
    uint32_t magic;         // 0x44565753 "DVWS"
    uint32_t filename_len;  // declared filename length
    char reserved[56];
};

}  // namespace

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

    // Size the decode buffer with the shared estimator, then decode
    // into it. estimate_decoded_length() counts every '%' as the start
    // of a well-formed %XX escape (one output byte); the decoder above
    // copies malformed escapes like "%GZ" verbatim (three output
    // bytes), so input laced with them decodes past the estimate.
    size_t decoded_len = estimate_decoded_length(status_pos);
    char* status_msg = (char*)malloc(decoded_len + 1);
    if (status_msg == nullptr) {
        http::send_json(client_socket,
                        "{\"status\": \"error\", \"message\": \"Allocation failed.\"}",
                        "", head_only);
        return;
    }
    decode_status_param(status_pos, status_msg);
    fprintf(stderr, "[status] %s\n", status_msg);

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
    std::string filename_length_str = req.header("X-Filename-Length");
    if (filename_length_str.empty()) {
        http::send_json(client_socket,
                        "{\"status\": \"error\", \"message\": \"Missing X-Filename-Length.\"}",
                        "", head_only);
        return;
    }

    unsigned int content_len =
        (unsigned int)strtoul(content_length_str.c_str(), nullptr, 10);
    unsigned int filename_len =
        (unsigned int)strtoul(filename_length_str.c_str(), nullptr, 10);

    // The header, body length and filename length are summed in 32-bit
    // arithmetic. Declared lengths near UINT_MAX wrap the total to a
    // small allocation, while the copy below still uses the original
    // content_len for both the offset and the length.
    uint32_t allocation =
        (uint32_t)sizeof(UploadHeader) + content_len + filename_len;
    char* file_buffer = (char*)malloc(allocation);
    if (file_buffer) {
        UploadHeader header{};
        header.magic = 0x44565753u;
        header.filename_len = filename_len;
        memcpy(file_buffer, &header, sizeof(header));
        recv(client_socket, file_buffer + sizeof(UploadHeader), content_len, 0);
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

    if (type == "static") {
        StaticRoute* rule = new StaticRoute();
        rule->path = path;
        rule->directory = url_decode(params["directory"]);
        cgi_rules().push_back(rule);
        route_types()[path] = RouteType::STATIC;
    } else if (type == "cgi") {
        CgiRoute* rule = new CgiRoute();
        rule->path = path;
        rule->executable = url_decode(params["executable"]);
        cgi_rules().push_back(rule);
        route_types()[path] = RouteType::CGI;
    } else {
        http::send_json(client_socket,
                        "{\"status\": \"error\", \"message\": \"Unknown type. Use ?type=static or ?type=cgi\"}",
                        "", req.method == "HEAD");
        return;
    }

    http::send_json(client_socket,
                    "{\"status\": \"ok\", \"message\": \"Rule added.\", \"rules\": " +
                        std::to_string(cgi_rules().size()) + "}",
                    "", req.method == "HEAD");
}

void update_rule(int client_socket, const HttpRequest& req) {
    auto params = extract_query_parameters(req.raw);
    std::string path = params["path"];
    std::string type = params["type"];

    if (route_types().find(path) == route_types().end()) {
        http::send_json(client_socket,
                        "{\"status\": \"error\", \"message\": \"No rule registered for that path.\"}",
                        "", req.method == "HEAD");
        return;
    }

    RouteType new_type;
    if (type == "static") {
        new_type = RouteType::STATIC;
    } else if (type == "cgi") {
        new_type = RouteType::CGI;
    } else {
        http::send_json(client_socket,
                        "{\"status\": \"error\", \"message\": \"Unknown type. Use ?type=static or ?type=cgi\"}",
                        "", req.method == "HEAD");
        return;
    }

    // Rewrite only the router's metadata entry; the Route object it
    // describes is left as-is. The tag and the object's actual class
    // can therefore disagree, and dispatch in handlers/cgi.cpp casts
    // based on the tag.
    route_types()[path] = new_type;

    http::send_json(client_socket,
                    "{\"status\": \"ok\", \"message\": \"Rule updated.\"}",
                    "", req.method == "HEAD");
}

void logging(int client_socket, const HttpRequest& req) {
    auto params = extract_query_parameters(req.raw);
    std::string output = params["output"];

    // install_log_sink() deletes the outgoing sink immediately;
    // records already queued for the async worker still hold the old
    // pointer (see logging_sink.cpp).
    if (output == "file") {
        install_log_sink(new FileLogSink());
        http::send_json(client_socket,
                        "{\"status\": \"ok\", \"message\": \"Logging output set to file.\"}",
                        "", req.method == "HEAD");
    } else if (output == "syslog") {
        install_log_sink(new SyslogLogSink());
        http::send_json(client_socket,
                        "{\"status\": \"ok\", \"message\": \"Logging output set to syslog.\"}",
                        "", req.method == "HEAD");
    } else {
        http::send_json(client_socket,
                        "{\"status\": \"error\", \"message\": \"Unknown output. Use ?output=file or ?output=syslog\"}",
                        "", req.method == "HEAD");
    }
}

void whoami(int client_socket, const HttpRequest& req) {
    // Extract the caller's username from the Basic Auth header so the
    // identity record below can echo it back.
    std::string auth = req.header("Authorization");
    std::string username, password;
    if (auth.empty() || !extract_username_password(auth, username, password)) {
        http::send_status(client_socket, "401 Unauthorized", "application/json",
                          "{\"status\": \"error\", \"message\": \"no credentials\"}",
                          "", req.method == "HEAD");
        return;
    }

    // Identity records are a fixed 128 bytes on the wire so that
    // downstream tooling can parse them without a length-prefixed
    // protocol. snprintf() writes only strlen("username=...") + 1
    // bytes of the record; the whole 128-byte buffer is transmitted
    // regardless, so everything past the terminating NUL is whatever
    // the stack held from earlier request handling on this thread.
    char response[128];
    snprintf(response, sizeof(response), "username=%s\n", username.c_str());

    // HEAD requests send headers only; Content-Length still reports
    // the full record size.
    http::send_status(client_socket, "200 OK", "application/octet-stream",
                      std::string(response, sizeof(response)), "",
                      req.method == "HEAD");
}

}
