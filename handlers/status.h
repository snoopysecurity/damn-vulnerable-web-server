// handlers/status.h
//
// Unauthenticated /status endpoint. Reports uptime and total request
// count.
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
