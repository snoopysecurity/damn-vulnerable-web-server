#ifndef REQUEST_LOGGER_H
#define REQUEST_LOGGER_H

#include <string>

// Vulnerable struct for Use-After-Free
typedef void (*LogFuncPtr)(const char*, const char*);

struct LogFormat {
    char format_string[64];
    LogFuncPtr log_func;
};

void log_request_response(const std::string& request, const std::string& response);
void handle_log_viewer(int client_socket, const std::string& request);

// New handler for logger configuration
void handle_logger_config(int client_socket, const std::string& request);

#endif // REQUEST_LOGGER_H
