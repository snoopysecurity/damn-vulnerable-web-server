#ifndef REQUEST_LOGGER_H
#define REQUEST_LOGGER_H

#include <string>

// Standard synchronous access logging (runs when no LogSink is
// installed via /admin/logging) and the log viewer.
void log_request_response(const std::string& request, const std::string& response);
void handle_log_viewer(int client_socket, const std::string& request);

#endif // REQUEST_LOGGER_H
