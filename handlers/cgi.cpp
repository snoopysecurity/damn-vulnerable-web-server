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
            // The router's metadata map decides how a rule is invoked.
            // --- INTENTIONAL VULNERABILITY (CWE-843, blind static_cast) ---
            // The metadata entry and the object's actual class can
            // disagree (see /admin/update_rule, which rewrites the tag
            // without reconstructing the object). A StaticRoute tagged
            // CGI is cast to CgiRoute* and its `directory` string is
            // interpreted as `executable`.
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
