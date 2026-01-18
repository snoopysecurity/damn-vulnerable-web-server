#include <cstdio>
#include <ctime>
#include <fstream>
#include <iostream>
#include "authentication.h" // Assuming extract_query_parameters is defined here
#include <sys/socket.h>
#include <cstring>       // for strerror()
#include <sstream>       // for stringstream
#include "utils.h"
#include "request_logger.h"
#include <cstdlib> // for malloc/free

// Global pointer for UAF vulnerability
LogFormat* current_log_format = nullptr;

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

    // Log to file
    FILE* log_file = fopen("/tmp/server.log", "a");
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
        std::string error_msg = "HTTP/1.1 500 Internal Server Error\r\n\r\nFailed to read logs.\n";
        send(client_socket, error_msg.c_str(), error_msg.length(), 0);
        return;
    }

    char buffer[256];
    std::stringstream result_stream;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result_stream << buffer;
    }

    pclose(pipe);
    std::string result = result_stream.str();

    std::string response;
    if (result.empty()) {
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nNo matching log entries found.\n";
    } else {
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + result;
    }

    send(client_socket, response.c_str(), response.length(), 0);
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
        
        response_body = "Log format updated.";
    } 
    else if (action == "reset") {
        if (current_log_format != nullptr) {
            free(current_log_format);
            // VULNERABILITY: Dangling pointer!
            // We do NOT set current_log_format = nullptr;
        }
        response_body = "Log format reset (memory freed).";
    } 
    else {
        response_body = "Unknown action. Use ?action=set&format=... or ?action=reset";
    }

    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + response_body;
    send(client_socket, response.c_str(), response.length(), 0);
}
