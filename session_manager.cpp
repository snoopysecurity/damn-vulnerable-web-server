#include "response_handler.h"  // Include the response handler header, not the source file
#include <iostream>
#include <unordered_map>
#include <string>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>

// Global map to store session data (for simplicity)
std::unordered_map<std::string, std::string> sessions;  // session_id -> user_data

// Generate a session ID: PRNG output mixed with the process ID.
std::string generate_session_id() {
    srand(time(0));
    uint32_t a = (uint32_t)rand();
    uint32_t b = (uint32_t)getpid();
    char buf[32];
    snprintf(buf, sizeof(buf), "SESSION_%08x", a ^ b);
    return std::string(buf);
}

void set_session_cookie(int client_socket, const std::string& session_id) {
    std::string cookie_header = "Set-Cookie: session_id=" + session_id + "; HttpOnly; Path=/\r\n";
    std::string response_body = "Session Created";

    send_200_response(client_socket, response_body, cookie_header);
}

std::string get_session_id_from_cookie(const std::string& request) {
    size_t cookie_pos = request.find("Cookie:");
    if (cookie_pos == std::string::npos) {
        return "";
    }

    size_t session_pos = request.find("session_id=", cookie_pos);
    if (session_pos == std::string::npos) {
        return "";
    }

    size_t start = session_pos + strlen("session_id=");
    size_t end = request.find(";", start);
    if (end == std::string::npos) {
        end = request.find("\r\n", start);
    }

    if (end != std::string::npos) {
        return request.substr(start, end - start);
    }

    return "";
}


// Function to set a session cookie (sends a Set-Cookie header to the client)
// This will set the cookie only if it's not already present
std::string set_session_cookie_if_needed(const std::string& request) {
    std::string session_id = get_session_id_from_cookie(request);

    if (session_id.empty()) {
        session_id = generate_session_id();
        sessions[session_id] = "default_user_data";  // Optionally store initial data
        return "Set-Cookie: session_id=" + session_id + "; HttpOnly; Path=/\r\n";
    }

    return "";  // No cookie needed, already exists
}

// Function to handle session expiration or invalidation (e.g., logout)
void invalidate_session(int client_socket) {
    std::string cookie = "Set-Cookie: session_id=; expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/\r\n";
    std::string response_body = "Session Expired";
    send_200_response(client_socket, response_body, cookie);  // Using the response handler to send response
}

// Function to check if a session is valid
bool is_valid_session(const std::string& session_id) {
    return sessions.find(session_id) != sessions.end();  // Check if the session_id exists in the map
}

// Function to set session data (like authentication status) for a session ID
void set_session_data(const std::string& session_id, const std::string& data) {
    sessions[session_id] = data;  // Store user data against the session ID
}

// Function to get session data (like authentication status) for a session ID
std::string get_session_data(const std::string& session_id) {
    if (sessions.find(session_id) != sessions.end()) {
        return sessions[session_id];  // Return user data if session exists
    }
    return "";
}




