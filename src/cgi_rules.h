// cgi_rules.h
//
// Route registry for /cgi-bin dispatch. Route objects form a normal
// C++ hierarchy; the router additionally keeps a metadata map
// (path -> RouteType) that /admin/update_rule can rewrite without
// reconstructing the object it describes.
#ifndef DVWS_CGI_RULES_H
#define DVWS_CGI_RULES_H

#include <map>
#include <string>
#include <vector>

// Router-side metadata. Duplicates the information already encoded in
// each object's C++ class -- kept for O(1) dispatch decisions.
enum class RouteType {
    STATIC,
    CGI,
};

class Route {
public:
    virtual ~Route() = default;
    std::string path;
};

// Serves files from a fixed directory.
class StaticRoute : public Route {
public:
    std::string directory;
};

// Runs an external executable per request.
class CgiRoute : public Route {
public:
    std::string executable;

    // Spawn the executable and stream its output back to the client.
    void execute(int client_socket) const;
};

// Global registries (kept as function-local statics so we do not need
// to expose another loose-globals compilation unit).
std::vector<Route*>& cgi_rules();
std::map<std::string, RouteType>& route_types();

#endif
