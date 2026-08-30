// handlers/cgi.cpp
#include "cgi.h"

#include "../cgi_rules.h"
#include "../http/response.h"

#include <cstring>
#include <iostream>

namespace handlers {

bool cgi_dispatch(int client_socket, const HttpRequest& req) {
    if (strncmp(req.clean_path, "/cgi-bin/", 9) != 0) return false;

    for (Route* rule : cgi_rules()) {
        if (rule->path == req.clean_path) {
            // Dispatch is decided by the router's metadata map, not by
            // the object's actual class: a rule tagged CGI is cast to
            // CgiRoute* and its first string member is read as
            // `executable`.
            if (route_types()[rule->path] != RouteType::CGI) {
                continue;
            }
            CgiRoute* cgi = static_cast<CgiRoute*>(rule);
            std::cout << "Executing rule for " << req.clean_path << std::endl;
            cgi->execute(client_socket);
            return true;
        }
    }
    return false;
}

}
