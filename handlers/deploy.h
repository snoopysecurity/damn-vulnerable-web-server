// handlers/deploy.h
//
// Quick Deploy feature: upload a .zip containing static HTML/CSS/JS
// and extract it to serve/deploy/ for immediate serving.
//
// CH-14: Zip Slip vulnerability - extraction does not validate paths,
// allowing malicious ZIP entries with ../ to escape the deployment
// directory.

#ifndef HANDLERS_DEPLOY_H_
#define HANDLERS_DEPLOY_H_

#include "../http/request.h"

namespace handlers {

// POST /admin/deploy_site - accepts a multipart/form-data upload
// containing a ZIP archive. Extracts the ZIP to serve/deploy/ without
// path validation (VULNERABLE to zip slip).
void deploy_site(int client_socket, const HttpRequest& req);

}  // namespace handlers

#endif  // HANDLERS_DEPLOY_H_
