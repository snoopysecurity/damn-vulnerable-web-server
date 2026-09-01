// handlers/status.cpp
#include "status.h"
#include "../http/response.h"
#include "../server_config.h"
#include "../utils.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>

namespace handlers {

namespace {

using clock_t_ = std::chrono::steady_clock;

const clock_t_::time_point kStartTime = clock_t_::now();
std::atomic<uint64_t> g_request_count{0};

// Minimal JSON string escaping for the docroot/helper values (they come
// from argv and the executable path, so quotes/backslashes are unlikely
// but must not be able to break the document).
std::string json_escape(const char* s) {
    std::string out;
    for (const char* p = (s != nullptr) ? s : ""; *p != '\0'; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20) {
            char buf[8];
            snprintf(buf, sizeof(buf), "\\u%04x", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

}  // namespace

void status_bump_request_counter() {
    g_request_count.fetch_add(1, std::memory_order_relaxed);
}

void status(int client_socket, const HttpRequest& req) {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                      clock_t_::now() - kStartTime).count();

    const char* helper_path = get_cgi_helper_path();
    std::string helper_json = (helper_path != nullptr)
        ? "\"" + json_escape(helper_path) + "\""
        : "null";

    std::ostringstream body;
    body << "{\n"
          << "  \"service\": \"damn-vulnerable-web-server\",\n"
          << "  \"version\": \"" << http::kServerBanner << "\",\n"
          << "  \"docroot\": \"" << json_escape(g_config.server_dir) << "\",\n"
          << "  \"cgi_helper\": " << helper_json << ",\n"
         << "  \"uptime_seconds\": " << uptime << ",\n"
         << "  \"requests_handled\": " << g_request_count.load(std::memory_order_relaxed) << ",\n"
         << "  \"warning\": \"intentionally-vulnerable-do-not-expose-publicly\"\n"
         << "}\n";

    http::send_status(client_socket, "200 OK", "application/json", body.str(),
                      "", req.method == "HEAD");
}

}  // namespace handlers
