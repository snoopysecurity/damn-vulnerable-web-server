// router.h
//
// Central request dispatcher.
#ifndef DVWS_ROUTER_H
#define DVWS_ROUTER_H

#include "http/request.h"

// Top-level entry point. Owns closing `client_socket`.
void dispatch(int client_socket, const char* raw_request);

#endif
