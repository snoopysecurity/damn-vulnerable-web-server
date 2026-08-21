// handlers/cgi.h
#ifndef DVWS_HANDLERS_CGI_H
#define DVWS_HANDLERS_CGI_H

#include "../http/request.h"

namespace handlers {

// Returns true if the request was handled (matched a /cgi-bin/ rule).
bool cgi_dispatch(int client_socket, const HttpRequest& req);

}

#endif
