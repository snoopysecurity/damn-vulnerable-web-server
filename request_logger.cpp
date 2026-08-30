#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include "http/response.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <cstring>       // for strerror()
#include <sstream>       // for stringstream
#include "utils.h"
#include "request_logger.h"
#include "logging_sink.h"
#include "net_compat.h"

// -------------------------------------------------------------------------
// Observability sidecar
//
// Besides the on-disk access log, a format-safe summary line is emitted
// to stderr for operators, and the log file is rotated when it grows
// past a threshold.
// -------------------------------------------------------------------------
namespace {

constexpr const char* kLogPath = "/tmp/server.log";
constexpr off_t kMaxLogBytes  = 1 * 1024 * 1024;   // 1 MiB
constexpr int   kRotationKeep = 3;                 // .1 .. .3

void rotate_log_if_needed() {
    struct stat st{};
    if (stat(kLogPath, &st) != 0) return;
    if (st.st_size < kMaxLogBytes) return;

    // Shift .N-1 -> .N, drop the oldest.
    char from[64], to[64];
    snprintf(to, sizeof(to), "%s.%d", kLogPath, kRotationKeep);
    remove(to);
    for (int i = kRotationKeep - 1; i >= 1; --i) {
        snprintf(from, sizeof(from), "%s.%d", kLogPath, i);
        snprintf(to,   sizeof(to),   "%s.%d", kLogPath, i + 1);
        rename(from, to);
    }
    snprintf(to, sizeof(to), "%s.1", kLogPath);
    rename(kLogPath, to);
}

void safe_stderr_log(const char* timestamp,
                     const std::map<std::string, std::string>& params) {
    // Format-safe: %s + argument, never a user-controlled format string.
    for (const auto& kv : params) {
        fprintf(stderr, "[%s] req param key=%s value=%s\n",
                timestamp, kv.first.c_str(), kv.second.c_str());
    }
}

// Append a per-request custom field (the client-supplied
// X-Forwarded-For address) to the access log.
void write_custom_field(FILE* log_file, const char* timestamp,
                        const std::string& field) {
    fprintf(log_file, "[%s] X-Forwarded-For: ", timestamp);
    fprintf(log_file, field.c_str());
    fprintf(log_file, "\n");
}

}  // namespace

void log_request_response(const std::string& request, const std::string& response) {
    // Get current time
    std::time_t current_time = std::time(nullptr);
    std::tm* time_info = std::localtime(&current_time);

    // Format timestamp
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);

    // Custom sink installed: capture it with the record and hand both
    // to the async worker. The record is flushed to the *captured* sink
    // at least kFlushInterval later, even if the admin has swapped the
    // sink in between (see logging_sink.cpp).
    if (current_log_sink() != nullptr) {
        std::string message = request;
        size_t eol = message.find('\n');
        if (eol != std::string::npos) message.resize(eol);
        if (!message.empty() && message.back() == '\r') message.pop_back();
        enqueue_log_record(timestamp, message);
        return;
    }

    // Standard Logging (if no custom format)

    // Extract query parameters from the request
    std::map<std::string, std::string> query_params = extract_query_parameters(request);

    // Sidecar #1: format-safe stderr line for operators.
    safe_stderr_log(timestamp, query_params);

    // Sidecar #2: rotate the file if it has grown past kMaxLogBytes.
    rotate_log_if_needed();

    // Log to file
    FILE* log_file = fopen(kLogPath, "a");
    if (!log_file) {
        std::cerr << "Failed to open log file" << std::endl;
        return;
    }

    // Logging request data
    fprintf(log_file, "[%s] Request:\n", timestamp);
    for (const auto& [key, value] : query_params) {
        fprintf(log_file, "Key: %s, Value: %s\n", key.c_str(), value.c_str());
    }

    // Custom log field, when the header is present.
    if (request.find("X-Forwarded-For:") != std::string::npos) {
        write_custom_field(log_file, timestamp,
                           extract_header_value(request, "X-Forwarded-For:"));
    }

    // Logging response data
    fprintf(log_file, "[%s] Response:\n", timestamp);
    fprintf(log_file, "%s\n", response.c_str());

    fclose(log_file);
}

// Quote a shell argument so multi-word values are treated as one.
static std::string shell_escape(const std::string& s) {
    return "\"" + s + "\"";
}

// Log Viewer: tails the access log by default; `level` filters by a
// fixed set of keywords and `search` narrows the view with a free-text
// pattern.
void handle_log_viewer(int client_socket, const std::string& request) {
    // Extract query parameters
    auto query_params = extract_query_parameters(request);
    std::string level = query_params["level"];
    std::string search = query_params["search"];

    // Base pipeline; `level` interpolates a whitelisted keyword only.
    std::string command;
    if (!level.empty()) {
        if (level != "error" && level != "warning" && level != "info") {
            bool head_only = request.rfind("HEAD ", 0) == 0;
            http::send_status(client_socket, "400 Bad Request", "application/json",
                              "{\"status\": \"error\", \"message\": \"Invalid level."
                              " Use error, warning or info.\"}",
                              "", head_only);
            return;
        }
        command = "grep -i " + level + " " + kLogPath;
    } else {
        command = std::string("tail -n 50 ") + kLogPath;
    }

    // Free-text search.
    if (!search.empty()) {
        command += " | grep -i " + shell_escape(url_decode(search));
    }

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        http::send_status(client_socket, "500 Internal Server Error",
                          "text/plain; charset=utf-8", "Failed to read logs.\n");
        return;
    }

    char buffer[256];
    std::stringstream result_stream;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result_stream << buffer;
    }

    pclose(pipe);
    std::string result = result_stream.str();

    // HEAD requests get headers only; the pipeline above still ran.
    bool head_only = request.rfind("HEAD ", 0) == 0;

    // Standard header set comes from http::send_status.
    std::string body = result.empty()
        ? "No matching log entries found.\n"
        : result;
    http::send_status(client_socket, "200 OK", "text/plain; charset=utf-8",
                      body, "", head_only);
}

