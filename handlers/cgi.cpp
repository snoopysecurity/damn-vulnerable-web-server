// handlers/cgi.cpp
#include "cgi.h"

#include "../cgi_rules.h"
#include "../http/response.h"

#include <cstring>
#include <iostream>

namespace handlers {

bool cgi_dispatch(int client_socket, const HttpRequest& req) {
    if (strncmp(req.clean_path, "/cgi-bin/", 9) != 0) return false;

    for (Rule* rule : cgi_rules()) {
        if (rule->path == req.clean_path) {
            // --- INTENTIONAL VULNERABILITY (CWE-843, blind static_cast) ---
            ExecRule* exec = static_cast<ExecRule*>(rule);
            std::cout << "Executing rule for " << req.clean_path << std::endl;
            if (exec->callback) {
                exec->callback(req.raw);  // controlled call!
            }
            http::send_ok(client_socket, "Executed.");
            return true;
        }
    }
    return false;
}

}
