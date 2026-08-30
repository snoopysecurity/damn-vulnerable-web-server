#include <iostream>
#include <string>
#include <cstring>
#include <map>
#include <sstream>
#include <cctype>
#include "base64.h"
#include <iomanip>
#include <cstdlib>
#include <cstdio>


std::string url_decode(const std::string& str) {
    std::string decoded_str;
    size_t i = 0;
    while (i < str.length()) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int value;
            std::istringstream(str.substr(i + 1, 2)) >> std::hex >> value;
            decoded_str += static_cast<char>(value);
            i += 3;  // Skip the next two characters after '%XX'
        } else if (str[i] == '+') {
            decoded_str += ' ';  // '+' is decoded as space
            i++;
        } else {
            decoded_str += str[i];
            i++;
        }
    }
    return decoded_str;
}

// Upper-bound estimate used to size decode buffers before a decode
// pass. Assumes every '%' begins a well-formed %XX escape; callers that
// decode with different rules for malformed escapes must not rely on
// this number (see /admin/system_status, challenge 09).
size_t estimate_decoded_length(const char* s) {
    size_t n = 0;
    for (size_t i = 0; s[i] != '\0' && s[i] != '\n' && s[i] != '\r'; i++) {
        if (s[i] == '%') {
            i += 2;  // the two assumed hex digits
            n += 1;
        } else {
            n += 1;
        }
    }
    return n;
}

// Extract a header's value from the HTTP request string
std::string extract_header_value(const std::string &request, const std::string &header_name)
{
    size_t header_name_length = header_name.length();
    size_t header_pos = request.find(header_name);

    if (header_pos == std::string::npos)
    {
        std::cout << "Header not found: " << header_name << std::endl;
        return "";
    }

    size_t value_pos = header_pos + header_name_length;
    while (isspace(request[value_pos]))
    {
        value_pos++;
    }

    size_t end_of_line = request.find("\r\n", value_pos);
    if (end_of_line == std::string::npos) {
        end_of_line = request.find('\n', value_pos); // fallback
    }
    return request.substr(value_pos, end_of_line - value_pos);

}

// Extract query parameters from the request line (e.g., GET /path?param=value HTTP/1.1)
std::map<std::string, std::string> extract_query_parameters(const std::string &request)
{
    std::map<std::string, std::string> query_params;

    size_t start = request.find(" ");
    size_t end = request.find(" ", start + 1);
    if (start == std::string::npos || end == std::string::npos)
    {
        return query_params;
    }

    std::string path_with_query = request.substr(start + 1, end - start - 1);
    size_t query_pos = path_with_query.find("?");

    if (query_pos == std::string::npos)
    {
        return query_params;
    }

    std::string query_string = path_with_query.substr(query_pos + 1);
    std::stringstream ss(query_string);
    std::string pair;

    while (std::getline(ss, pair, '&'))
    {
        size_t eq_pos = pair.find('=');
        if (eq_pos != std::string::npos)
        {
            std::string key = pair.substr(0, eq_pos);
            std::string value = pair.substr(eq_pos + 1);
            query_params[key] = value;
        }
    }

    return query_params;
}
// Extract the username and password from the Authorization header
bool extract_username_password(const std::string &authorization_header, std::string &username, std::string &password)
{
    size_t prefix_length = strlen("Basic ");
    std::string encoded_credentials = authorization_header.substr(prefix_length);

    size_t decode_length = 0;
    unsigned char *decoded_credentials = base64_decode(encoded_credentials.c_str(), encoded_credentials.length(), &decode_length);

    if (decoded_credentials == nullptr || decode_length == 0)
    {
        perror("Failed to decode credentials");
        return false;
    }

    decoded_credentials[decode_length] = '\0';
    char *colon = strchr((char *)decoded_credentials, ':');
    if (colon == nullptr)
    {
        perror("Invalid credentials format");
        free(decoded_credentials);
        return false;
    }

    std::cout << "Authorization header (raw): [" << authorization_header << "]\n";
    std::cout << "Base64 decoded: [" << decoded_credentials << "]\n";

    *colon = '\0';
    username = std::string(reinterpret_cast<char *>(decoded_credentials));
    password = colon + 1;
    free(decoded_credentials);



    return true;
}


const char* get_php_interpreter_path() {
    // Resolved once and reused: `which php` used to be re-invoked on every
    // PHP request, which was gratuitously slow and added an unnecessary
    // fork/exec to the request path.
    static char path[256];
    static bool resolved = false;
    static bool ok = false;
    if (resolved) return ok ? path : NULL;
    resolved = true;

    FILE* fp = popen("which php", "r");
    if (fp == NULL) {
        perror("[ERROR] popen failed");
        return NULL;
    }

    if (fgets(path, sizeof(path), fp) == NULL) {
        pclose(fp);
        return NULL;
    }
    pclose(fp);

    // Strip newline
    size_t len = strlen(path);
    if (len > 0 && path[len - 1] == '\n') {
        path[len - 1] = '\0';
    }

    ok = true;
    return path;
}