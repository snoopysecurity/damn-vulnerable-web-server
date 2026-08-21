// handlers/static_files.h
#ifndef DVWS_HANDLERS_STATIC_H
#define DVWS_HANDLERS_STATIC_H

#include "../http/request.h"
#include <string>

namespace handlers {

void serve_static(int client_socket, const HttpRequest& req,
                  const std::string& set_cookie_header);

}

#endif
