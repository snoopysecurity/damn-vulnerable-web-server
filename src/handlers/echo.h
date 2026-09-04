// handlers/echo.h
//
// Unauthenticated /echo request-echo debug page.
#ifndef DVWS_HANDLERS_ECHO_H
#define DVWS_HANDLERS_ECHO_H

#include "../http/request.h"

namespace handlers {

void echo_request(int client_socket, const HttpRequest& req);

}

#endif
