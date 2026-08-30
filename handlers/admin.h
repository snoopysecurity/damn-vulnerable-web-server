// handlers/admin.h
#ifndef DVWS_HANDLERS_ADMIN_H
#define DVWS_HANDLERS_ADMIN_H

#include "../http/request.h"

namespace handlers {

// Each of these assumes the caller has already Basic-Auth'd the client.
// They all take ownership of finalizing the response for their route.

void system_status(int client_socket, const HttpRequest& req);
void upload_file  (int client_socket, const HttpRequest& req);
void add_rule     (int client_socket, const HttpRequest& req);
void update_rule  (int client_socket, const HttpRequest& req);
void logging      (int client_socket, const HttpRequest& req);
void whoami       (int client_socket, const HttpRequest& req);

}

#endif
