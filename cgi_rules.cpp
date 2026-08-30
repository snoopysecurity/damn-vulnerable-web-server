// cgi_rules.cpp
#include "cgi_rules.h"

#include "http/response.h"

#include <cstdio>
#include <sstream>

std::vector<Route*>& cgi_rules() {
    static std::vector<Route*> rules;
    return rules;
}

std::map<std::string, RouteType>& route_types() {
    static std::map<std::string, RouteType> types;
    return types;
}

void CgiRoute::execute(int client_socket) const {
    FILE* pipe = popen(executable.c_str(), "r");
    if (pipe == nullptr) {
        http::send_status(client_socket, "500 Internal Server Error",
                          "text/plain; charset=utf-8",
                          "Failed to execute rule.\n");
        return;
    }

    std::stringstream result_stream;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result_stream << buffer;
    }
    pclose(pipe);

    std::string result = result_stream.str();
    http::send_status(client_socket, "200 OK", "text/plain; charset=utf-8",
                      result.empty() ? "Executed.\n" : result);
}
