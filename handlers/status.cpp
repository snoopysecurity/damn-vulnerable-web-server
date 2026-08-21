// handlers/status.cpp
#include "status.h"
#include "../http/response.h"

#include <atomic>
#include <chrono>
#include <sstream>

namespace handlers {

namespace {

using clock_t_ = std::chrono::steady_clock;

const clock_t_::time_point kStartTime = clock_t_::now();
std::atomic<uint64_t> g_request_count{0};

}  // namespace

void status_bump_request_counter() {
    g_request_count.fetch_add(1, std::memory_order_relaxed);
}

void status(int client_socket, const HttpRequest& /*req*/) {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                      clock_t_::now() - kStartTime).count();

    std::ostringstream body;
    body << "{\n"
         << "  \"service\": \"damn-vulnerable-web-server\",\n"
         << "  \"uptime_seconds\": " << uptime << ",\n"
         << "  \"requests_handled\": " << g_request_count.load(std::memory_order_relaxed) << ",\n"
         << "  \"warning\": \"intentionally-vulnerable-do-not-expose-publicly\"\n"
         << "}\n";

    http::send_status(client_socket, "200 OK", "application/json", body.str());
}

}  // namespace handlers
