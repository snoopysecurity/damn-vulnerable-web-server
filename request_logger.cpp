#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include "authentication.h" // Assuming extract_query_parameters is defined here
#include "http/response.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <cstring>       // for strerror()
#include <sstream>       // for stringstream
#include "utils.h"
#include "request_logger.h"
#include "net_compat.h"
#include <cstdlib> // for malloc/free

// Global pointer for UAF vulnerability
LogFormat* current_log_format = nullptr;

// -------------------------------------------------------------------------
// Observability sidecar
//
// The primary /tmp/server.log write below intentionally uses the caller's
// value as a printf format string (CH-03, CWE-134). To give operators a
// safe, out-of-band view of what's happening, we *also* emit a
// format-safe line to stderr and rotate the log file when it grows past
// a threshold. Neither of these mitigates or interferes with the
// intentional vulnerability.
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

}  // namespace

void default_custom_logger(const char* timestamp, const char* message) {
    FILE* log_file = fopen("/tmp/server.log", "a");
    if (log_file) {
        fprintf(log_file, "[CUSTOM] [%s] %s\n", timestamp, message);
        fclose(log_file);
    }
}

void log_request_response(const std::string& request, const std::string& response) {
    // Get current time
    std::time_t current_time = std::time(nullptr);
    std::tm* time_info = std::localtime(&current_time);

    // Format timestamp
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);

    // VULNERABILITY: Use-After-Free
    // If current_log_format was freed but not nulled, this checks true
    // and accesses freed memory.
    if (current_log_format != nullptr) {
        // If memory was reallocated and overwritten, log_func might be a controlled pointer
        current_log_format->log_func(timestamp, "Custom format logging enabled");
        return; 
    }

    // Standard Logging (if no custom format)

    // Extract query parameters from the request
    std::map<std::string, std::string> query_params = extract_query_parameters(request);

    // Sidecar #1: format-safe stderr line for operators. Kept separate
    // from the on-disk log below so nothing here changes the primitive.
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
        fprintf(log_file, "Key: %s, Value: ", key.c_str());
        fprintf(log_file, value.c_str());  // format string issue preserved
        fprintf(log_file, "\n");
    }

    // Logging response data
    fprintf(log_file, "[%s] Response:\n", timestamp);
    fprintf(log_file, "%s\n", response.c_str());

    fclose(log_file);
}

// Log Viewer with Command Injection Vulnerability
void handle_log_viewer(int client_socket, const std::string& request) {
    // Extract query parameters
    auto query_params = extract_query_parameters(request);
    std::string filter = query_params["filter"];  // User-controlled filter parameter

    // URL-decode the filter string
    std::string decoded_filter = url_decode(filter);

    // Construct the command to execute. This will allow the attacker to inject commands
    std::string command = "sh -c \"grep " + decoded_filter + " /tmp/server.log;\"";

    // Execute the command using popen
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

    // HEAD requests get headers only; the grep above still ran (the
    // command-injection primitive is method-agnostic).
    bool head_only = request.rfind("HEAD ", 0) == 0;

    // Standard header set comes from http::send_status (REALISM_PLAN T4).
    std::string body = result.empty()
        ? "No matching log entries found.\n"
        : result;
    http::send_status(client_socket, "200 OK", "text/plain; charset=utf-8",
                      body, "", head_only);
}

// Handler for Logger Configuration (The UAF Trigger)
void handle_logger_config(int client_socket, const std::string& request) {
    auto params = extract_query_parameters(request);
    std::string action = params["action"];
    std::string response_body;

    if (action == "set") {
        if (current_log_format == nullptr) {
            // Allocate 72 bytes (64 char + 8 ptr)
            current_log_format = (LogFormat*)malloc(sizeof(LogFormat));
        }
        
        std::string format = params["format"];
        if (format.length() > 63) format = format.substr(0, 63);
        
        strcpy(current_log_format->format_string, format.c_str());
        current_log_format->log_func = default_custom_logger;
        
        response_body = "{\"status\": \"ok\", \"message\": \"Log format updated.\"}";
    } 
    else if (action == "reset") {
        if (current_log_format != nullptr) {
            free(current_log_format);
            // VULNERABILITY: Dangling pointer!
            // We do NOT set current_log_format = nullptr;
        }
        response_body = "{\"status\": \"ok\", \"message\": \"Log format reset (memory freed).\"}";
    } 
    else {
        response_body = "{\"status\": \"error\", \"message\": \"Unknown action. Use ?action=set&format=... or ?action=reset\"}";
    }

    // HEAD requests get headers only; the alloc/free logic above ran
    // identically (the UAF primitive is method-agnostic). JSON body per
    // REALISM_PLAN T8; standard header set via http::send_status.
    bool head_only = request.rfind("HEAD ", 0) == 0;
    http::send_status(client_socket, "200 OK", "application/json",
                      response_body, "", head_only);
}
