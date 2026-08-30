// handlers/admin.h
#ifndef DVWS_HANDLERS_ADMIN_H
#define DVWS_HANDLERS_ADMIN_H

#include "../http/request.h"

namespace handlers {

// Each of these assumes the caller has already Basic-Auth'd the client.
// They all take ownership of finalizing the response for their route.

void system_status(int client_socket, const HttpRequest& req);   // CWE-122
void upload_file  (int client_socket, const HttpRequest& req);   // CWE-190
void add_rule     (int client_socket, const HttpRequest& req);   // CWE-843 setup
void update_rule  (int client_socket, const HttpRequest& req);   // CWE-843 trigger
void logging      (int client_socket, const HttpRequest& req);   // CWE-416 trigger
void whoami       (int client_socket, const HttpRequest& req);   // CWE-125 info-leak

}

#endif
