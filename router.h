// router.h
//
// Central request dispatcher. Extracted from the former monolithic
// handle_request() in main.cpp so each intentional vulnerability lives
// in a dedicated handler file that maps cleanly to CHALLENGES.md.
#ifndef DVWS_ROUTER_H
#define DVWS_ROUTER_H

#include "http/request.h"

// Top-level entry point. Owns closing `client_socket`.
void dispatch(int client_socket, const char* raw_request);

#endif
