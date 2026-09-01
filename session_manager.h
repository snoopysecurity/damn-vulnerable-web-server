// session_manager.h

#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <string>
#include <unordered_map>

// Declare the session storage map
extern std::unordered_map<std::string, std::string> sessions;

// Session management API
std::string generate_session_id();
std::string set_session_cookie_if_needed(const std::string& request);
void invalidate_session(int client_socket);
bool is_valid_session(const std::string& session_id);
void set_session_data(const std::string& session_id, const std::string& data);
std::string get_session_data(const std::string& session_id);
void set_session_cookie(int client_socket, const std::string& session_id);

// Declare the function to extract session ID from cookies
std::string get_session_id_from_cookie(const std::string& request);

#endif  // SESSION_MANAGER_H