// http/response.cpp
#include "response.h"
#include "../server_config.h"
#include "net_compat.h"

#include <sys/socket.h>
#include <time.h>
#include <cstring>
#include <ctime>

namespace http {

std::string http_date(std::time_t t) {
    std::tm tm_buf{};
    gmtime_r(&t, &tm_buf);
    char buf[64];
    if (strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_buf) == 0) {
        return "";
    }
    return buf;
}

std::string http_date_now() {
    return http_date(std::time(nullptr));
}

std::string error_page(int status_code, const std::string& reason, const std::string& detail) {
    const std::string title = std::to_string(status_code) + " " + reason;
    std::string detail_html;
    if (!detail.empty()) {
        detail_html = "<p class=\"detail\">" + detail + "</p>\n";
    }
    return "<!DOCTYPE html>\n"
           "<html>\n"
           "<head>\n"
           "<meta charset=\"utf-8\">\n"
           "<title>" +
           title +
           "</title>\n"
           "<style>\n"
           "body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;"
           "background:#f4f4f4;color:#333;margin:0;padding:48px 16px}\n"
           ".card{max-width:520px;margin:0 auto;background:#fff;"
           "border:1px solid #ddd;border-radius:8px;padding:32px 40px;"
           "box-shadow:0 2px 6px rgba(0,0,0,.06)}\n"
           "h1{font-size:56px;margin:0 0 8px;color:#c0392b;letter-spacing:-2px}\n"
           "p{font-size:16px;line-height:1.5;margin:8px 0}\n"
           ".detail{font-family:ui-monospace,Menlo,Consolas,monospace;"
           "font-size:13px;background:#f8f8f8;border:1px solid #eee;"
           "border-radius:4px;padding:8px 12px;word-break:break-all}\n"
           "hr{border:0;border-top:1px solid #eee;margin:24px 0 12px}\n"
           "address{font-size:12px;color:#888;font-style:normal}\n"
           "</style>\n"
           "</head>\n"
           "<body>\n"
           "<div class=\"card\">\n"
           "<h1>" +
           std::to_string(status_code) +
           "</h1>\n"
           "<p>" +
           reason + "</p>\n" + detail_html +
           "<hr>\n"
           "<address>" +
           std::string(kServerBanner) + " Server at port " + std::to_string(g_config.port) +
           "</address>\n"
           "</div>\n"
           "</body>\n"
           "</html>\n";
}

void send_status(int client_socket, const std::string& status_code, const std::string& content_type,
                 const std::string& body, const std::string& extra_headers, bool head_only) {
    std::string header = "HTTP/1.1 " + status_code + "\r\n";
    header += "Content-Type: " + content_type + "\r\n";
    header += "Content-Length: " + std::to_string(body.length()) + "\r\n";
    if (!extra_headers.empty()) header += extra_headers;
    header += std::string("Server: ") + kServerBanner + "\r\n";
    header += "Date: " + http_date_now() + "\r\n";
    header += "Connection: close\r\n";
    header += "\r\n";

    send(client_socket, header.c_str(), header.length(), DVWS_SEND_FLAGS);
    if (!head_only && !body.empty()) {
        send(client_socket, body.c_str(), body.length(), DVWS_SEND_FLAGS);
    }
}

}  // namespace http
