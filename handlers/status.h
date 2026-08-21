// handlers/status.h
//
// Unauthenticated /status endpoint for workshop instructors.
// Reports uptime and total request count. Deliberately does not leak
// anything an attacker could use to bypass the intentional challenges.
#ifndef DVWS_HANDLERS_STATUS_H
#define DVWS_HANDLERS_STATUS_H

#include "../http/request.h"

namespace handlers {

void status(int client_socket, const HttpRequest& req);

// Called once from dispatch() per handled request so /status can report
// a running count.
void status_bump_request_counter();

}

#endif
