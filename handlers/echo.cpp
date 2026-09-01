// handlers/echo.cpp
//
// The /echo request-echo / debug page. Reports what the server actually
// saw on the wire for this invocation -- no caching, no filtering.
// Reflected values are HTML-escaped: this is a debug page, not an XSS lab.
#include "echo.h"

#include "../http/response.h"
#include "../server_config.h"
#include "../utils.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <sstream>
#include <string>

namespace handlers {

namespace {

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        switch (ch) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            default:   out += ch;       break;
        }
    }
    return out;
}

}  // namespace

void echo_request(int client_socket, const HttpRequest& req) {
    const bool head_only = (req.method == "HEAD");

    std::ostringstream page;
    page << "<!DOCTYPE html>\n"
         << "<html lang=\"en\">\n"
         << "<head>\n"
         << "<meta charset=\"utf-8\">\n"
         << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
         << "<title>Request Echo | DVWS</title>\n"
         << "<link rel=\"icon\" href=\"/favicon.ico\" sizes=\"any\">\n"
         << "<link rel=\"stylesheet\" href=\"/static/style.css\">\n"
         << "</head>\n"
         << "<body>\n"

         << "<header class=\"site\"><div class=\"container\">\n"
         << "<a class=\"brand\" href=\"/\"><img src=\"/static/logo.svg\" alt=\"\" "
            "width=\"28\" height=\"28\">Damn Vulnerable Web Server</a>\n"
         << "<nav><a href=\"/\">Home</a><a href=\"/projects.html\">Projects</a>"
            "<a href=\"/status\">Status</a></nav>\n"
         << "</div></header>\n"

         << "<main class=\"container\">\n"
         << "<section class=\"hero\">\n"
         << "<h1>Request Echo</h1>\n"
         << "<p class=\"lead\">Debug endpoint. This page reports exactly what the "
         << "server sees for the current invocation -- no caching, no filtering.</p>\n"
         << "</section>\n";

    // Request line as received.
    page << "<h2>Request</h2>\n"
         << "<table><tr><th>Key</th><th>Value</th></tr>\n"
         << "<tr><td>method</td><td><code>" << html_escape(req.method)
         << "</code></td></tr>\n"
         << "<tr><td>uri</td><td><code>" << html_escape(req.clean_path)
         << "</code></td></tr>\n"
         << "<tr><td>query</td><td><code>" << html_escape(req.query)
         << "</code></td></tr>\n"
         << "</table>\n";

    // Query parameters.
    const std::map<std::string, std::string> params =
        extract_query_parameters(req.raw);
    page << "<h2>GET</h2>\n";
    if (params.empty()) {
        page << "<p class='empty'>(none)</p>\n";
    } else {
        page << "<table><tr><th>Key</th><th>Value</th></tr>\n";
        for (const auto& kv : params) {
            page << "<tr><td>" << html_escape(kv.first) << "</td><td><code>"
                 << html_escape(kv.second) << "</code></td></tr>\n";
        }
        page << "</table>\n";
    }

    // A few representative headers the server actually parsed.
    static const char* const kEchoHeaders[] = {
        "Host:", "User-Agent:", "Accept:", "Accept-Encoding:", "Cookie:", "Connection:",
    };
    page << "<h2>Headers</h2>\n"
         << "<table><tr><th>Key</th><th>Value</th></tr>\n";
    for (const char* header : kEchoHeaders) {
        const std::string name(header, strlen(header) - 1);  // strip ':'
        page << "<tr><td>" << html_escape(name) << "</td><td><code>"
             << html_escape(req.header(name)) << "</code></td></tr>\n";
    }
    page << "</table>\n";

    // Server-side context (replaces the old interpreter panel).
    const char* helper_path = get_cgi_helper_path();
    char now[40];
    time_t t = time(nullptr);
    strftime(now, sizeof(now), "%Y-%m-%dT%H:%M:%S%z", localtime(&t));
    page << "<h2>Server</h2>\n"
         << "<table><tr><th>Key</th><th>Value</th></tr>\n"
         << "<tr><td>version</td><td><code>" << http::kServerBanner
         << "</code></td></tr>\n"
         << "<tr><td>docroot</td><td><code>" << html_escape(g_config.server_dir)
         << "</code></td></tr>\n"
         << "<tr><td>cgi_helper</td><td><code>"
         << (helper_path != nullptr ? html_escape(helper_path) : "(not found)")
         << "</code></td></tr>\n"
         << "<tr><td>time</td><td><code>" << now << "</code></td></tr>\n"
         << "</table>\n";

    page << "</main>\n"

         << "<footer class=\"site\"><div class=\"container\">\n"
         << "<p class=\"fingerprint\">debug endpoint -- output is escaped, the "
            "transport is not &middot; powered by <code>DVWS/1.0</code></p>\n"
         << "</div></footer>\n"

         << "</body>\n"
         << "</html>\n";

    http::send_status(client_socket, "200 OK", "text/html; charset=utf-8",
                      page.str(), "", head_only);
}

}
