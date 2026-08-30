// handlers/static_files.cpp
#include "static_files.h"

#include "../error_handling.h"
#include "../http/response.h"
#include "../mime_type_handler.h"
#include "../net_compat.h"
#include "../request_logger.h"
#include "../server_config.h"
#include "../utils.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <filesystem>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <vector>

namespace handlers {

// HTML-escape a filesystem entry name for the autoindex listing.
static std::string html_escape(const std::string& s) {
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

// nginx-style directory listing. Returns an empty string when the
// directory cannot be read.
static std::string autoindex_page(const std::string& fs_dir,
                                  const std::string& uri) {
    std::vector<std::string> names;
    DIR* dir = opendir(fs_dir.c_str());
    if (dir == nullptr) return "";
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        std::string name = ent->d_name;
        if (name == ".") continue;
        names.push_back(name);
    }
    closedir(dir);
    std::sort(names.begin(), names.end());

    std::ostringstream page;
    page << "<!DOCTYPE html>\n"
         << "<html>\n<head>\n<meta charset=\"utf-8\">\n"
         << "<title>Index of " << html_escape(uri) << "</title>\n"
         << "<style>\n"
         << "body{font-family:system-ui,-apple-system,sans-serif;background:#fff;"
            "color:#333;margin:32px}\n"
         << "h1{font-size:22px;font-weight:600}\n"
         << "pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:14px;"
            "line-height:1.7}\n"
         << "a{color:#0366d6;text-decoration:none}a:hover{text-decoration:underline}\n"
         << "hr{border:0;border-top:1px solid #ddd;margin:16px 0}\n"
         << "</style>\n</head>\n<body>\n"
         << "<h1>Index of " << html_escape(uri) << "</h1><hr><pre>";

    const std::string sep = (fs_dir.back() == '/') ? "" : "/";
    for (const std::string& name : names) {
        const std::string full = fs_dir + sep + name;
        struct stat st{};
        const bool have = (stat(full.c_str(), &st) == 0);
        const bool is_dir = have && S_ISDIR(st.st_mode);

        const std::string display = name + (is_dir ? "/" : "");
        const std::string esc = html_escape(display);

        std::string mtime = "-";
        std::string size = "-";
        if (have) {
            char buf[32];
            std::tm tm_buf{};
            localtime_r(&st.st_mtime, &tm_buf);
            if (strftime(buf, sizeof(buf), "%d-%b-%Y %H:%M", &tm_buf) > 0) {
                mtime = buf;
            }
            if (!is_dir) size = std::to_string(st.st_size);
        }

        // Pad the name column so the date/size columns line up, nginx-style.
        const size_t pad = (display.size() < 52) ? (52 - display.size()) : 1;
        page << "<a href=\"" << esc << "\">" << esc << "</a>"
             << std::string(pad, ' ') << mtime << "  " << size << "\n";
    }

    page << "</pre><hr></body>\n</html>\n";
    return page.str();
}

static void serve_file(int client_socket, const char* file_path,
                       const char* request_path,
                       const char* request,
                       const std::string& set_cookie_header,
                       bool head_only) {
    std::string response_header;

    // DirectoryIndex, Apache/nginx-style: when the mapped path is a
    // directory, serve its index document instead.
    char resolved_path[512];
    snprintf(resolved_path, sizeof(resolved_path), "%s", file_path);
    struct stat path_stat{};
    if (stat(resolved_path, &path_stat) == 0 && S_ISDIR(path_stat.st_mode)) {
        static const char* const kIndexDocs[] = {"index.html", "index.php"};
        bool index_found = false;
        for (const char* doc : kIndexDocs) {
            size_t len = strlen(resolved_path);
            const char* slash = (len > 0 && resolved_path[len - 1] != '/') ? "/" : "";
            char candidate[600];
            snprintf(candidate, sizeof(candidate), "%s%s%s", resolved_path, slash, doc);
            if (stat(candidate, &path_stat) == 0 && S_ISREG(path_stat.st_mode)) {
                snprintf(resolved_path, sizeof(resolved_path), "%s", candidate);
                index_found = true;
                break;
            }
        }
        if (!index_found) {
            // Autoindex: list the directory contents. Falls back to
            // 403 only if the directory cannot be read.
            std::string title = (request_path[0] != '\0') ? request_path : "/";
            std::string body = autoindex_page(resolved_path, title);
            if (body.empty()) {
                response_header = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n";
                send_error_response(client_socket, 403, "Forbidden", file_path, head_only ? 0 : 1);
                log_request_response(request, response_header);
                return;
            }
            response_header = "HTTP/1.1 200 OK\r\n";
            response_header += "Content-Type: text/html; charset=utf-8\r\n";
            response_header += "Content-Length: " + std::to_string(body.size()) + "\r\n";
            if (!set_cookie_header.empty()) response_header += set_cookie_header;
            response_header += std::string("Server: ") + http::kServerBanner + "\r\n";
            response_header += "Date: " + http::http_date_now() + "\r\n";
            response_header += "Connection: close\r\n";
            response_header += "\r\n";

            log_request_response(request, response_header);
            if (send(client_socket, response_header.c_str(), response_header.length(), DVWS_SEND_FLAGS) < 0) {
                perror("Failed to send response header");
                return;
            }
            if (!head_only) {
                send(client_socket, body.c_str(), body.length(), DVWS_SEND_FLAGS);
            }
            return;
        }
    }

    FILE* file = fopen(resolved_path, "r");

    if (file == nullptr) {
        perror("Failed to open file");
        response_header = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile Not Found";
        send_error_response(client_socket, 404, "Not Found", file_path, head_only ? 0 : 1);
        log_request_response(request, response_header);
        return;
    }

    if (check_php_file(resolved_path)) {
        // CGI-style response: no Content-Length; the connection close
        // delimits the body (standard behaviour for piped interpreter
        // output). Standard header set otherwise.
        response_header = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n";
        if (!set_cookie_header.empty()) response_header += set_cookie_header;
        response_header += std::string("Server: ") + http::kServerBanner + "\r\n";
        response_header += "Date: " + http::http_date_now() + "\r\n";
        response_header += "Connection: close\r\n";
        response_header += "\r\n";

        log_request_response(request, response_header);
        handle_php_file(file, &client_socket, response_header.c_str(), head_only ? 0 : 1);
        fclose(file);
        return;
    }

    // File metadata for Content-Length / Last-Modified / conditional
    // GET. fstat() on the open FILE* avoids a TOCTOU window; if it
    // fails we degrade to a close-delimited response.
    struct stat file_stat{};
    const bool have_stat = (fstat(fileno(file), &file_stat) == 0);
    const std::string last_modified =
        have_stat ? http::http_date(file_stat.st_mtime) : "";

    // Conditional GET: a byte-identical If-Modified-Since earns a 304.
    if (have_stat && !last_modified.empty()) {
        std::string ims = extract_header_value(request, "If-Modified-Since:");
        if (ims == last_modified) {
            response_header = "HTTP/1.1 304 Not Modified\r\n";
            response_header += "Last-Modified: " + last_modified + "\r\n";
            response_header += std::string("Server: ") + http::kServerBanner + "\r\n";
            response_header += "Date: " + http::http_date_now() + "\r\n";
            response_header += "Connection: close\r\n";
            response_header += "\r\n";

            log_request_response(request, response_header);
            send(client_socket, response_header.c_str(), response_header.length(), DVWS_SEND_FLAGS);
            fclose(file);
            return;
        }
    }

    const char* content_type = get_content_type(resolved_path);
    response_header = "HTTP/1.1 200 OK\r\n";
    response_header += std::string("Content-Type: ") + content_type + "\r\n";
    if (have_stat) {
        response_header += "Content-Length: " + std::to_string((long long)file_stat.st_size) + "\r\n";
        response_header += "Last-Modified: " + last_modified + "\r\n";
    }
    if (!set_cookie_header.empty()) response_header += set_cookie_header;
    response_header += std::string("Server: ") + http::kServerBanner + "\r\n";
    response_header += "Date: " + http::http_date_now() + "\r\n";
    response_header += "Connection: close\r\n";
    response_header += "\r\n";

    log_request_response(request, response_header);

    if (send(client_socket, response_header.c_str(), response_header.length(), DVWS_SEND_FLAGS) < 0) {
        perror("Failed to send response header");
        fclose(file);
        return;
    }

    if (head_only) {
        // HEAD: headers sent, body suppressed. (Connection close delimits
        // the response until the standard-header pass adds Content-Length.)
        fclose(file);
        return;
    }

    char file_buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
        if (send(client_socket, file_buffer, bytes_read, DVWS_SEND_FLAGS) < 0) {
            perror("Failed to send file");
            break;
        }
    }

    fclose(file);
}

void serve_static(int client_socket, const HttpRequest& req,
                  const std::string& set_cookie_header) {
    // Map the request path into the document root and resolve it.
    std::string docroot(g_config.server_dir);

    // The legacy parser yields an empty clean_path for "GET /" (the byte
    // right after "GET /" is the space that terminates the path). Map the
    // empty path onto the docroot with its trailing slash so the root URL
    // serves the directory index instead of bouncing to itself.
    std::string joined = docroot + req.clean_path;
    if (req.clean_path[0] == '\0') {
        joined += "/";
    }

    // Requests that map outside the document root are rejected.
    if (joined.rfind(docroot, 0) != 0) {
        http::send_status(client_socket, "403 Forbidden", "text/html; charset=utf-8",
                          http::error_page(403, "Forbidden",
                                           "The requested path is outside the document root."),
                          set_cookie_header, req.method == "HEAD");
        return;
    }

    // Resolve `..` segments and symlinks; a nonexistent tail is kept
    // lexically and surfaces as the 404 case below.
    std::error_code ec;
    std::string file_path =
        std::filesystem::weakly_canonical(std::filesystem::path(joined), ec).string();
    if (ec) {
        http::send_status(client_socket, "404 Not Found", "text/html; charset=utf-8",
                          http::error_page(404, "Not Found",
                                           "The requested path could not be resolved."),
                          set_cookie_header, req.method == "HEAD");
        return;
    }
    // weakly_canonical() drops a trailing separator; restore it.
    if (!joined.empty() && !file_path.empty() &&
        joined.back() == '/' && file_path.back() != '/') {
        file_path += "/";
    }

    bool head_only = (req.method == "HEAD");

    // A directory requested without its trailing slash gets a 301
    // redirect; this also keeps "/admin" (no slash) from serving
    // "/admin/index.php" around the router's "/admin/" auth prefix
    // check. Only printable, space-free paths are redirectable so the
    // Location header cannot carry injected CR/LF.
    struct stat path_stat{};
    size_t dir_len = file_path.length();
    if (dir_len > 0 && file_path[dir_len - 1] != '/' &&
        stat(file_path.c_str(), &path_stat) == 0 && S_ISDIR(path_stat.st_mode)) {
        bool redirectable = true;
        for (const char* p = req.clean_path; *p != '\0'; ++p) {
            unsigned char c = (unsigned char)*p;
            if (c < 0x21 || c > 0x7e) {
                redirectable = false;
                break;
            }
        }
        if (redirectable) {
            std::string location = std::string(req.clean_path) + "/";
            std::string extra = "Location: " + location + "\r\n" + set_cookie_header;
            http::send_status(client_socket, "301 Moved Permanently",
                              "text/html; charset=utf-8",
                              http::error_page(301, "Moved Permanently",
                                               "The document has moved."),
                              extra, head_only);
            return;
        }
    }

    serve_file(client_socket, file_path.c_str(), req.clean_path, req.raw,
               set_cookie_header, head_only);
}

}
