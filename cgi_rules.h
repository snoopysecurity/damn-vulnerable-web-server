// cgi_rules.h
//
// Backing store for the type-confusion challenge. Route objects form a
// normal C++ hierarchy; separately, the router keeps a metadata map
// (path -> RouteType) that is *supposed* to mirror each object's actual
// class. The two sources of truth can drift apart: /admin/update_rule
// rewrites the metadata entry without reconstructing the object.
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
