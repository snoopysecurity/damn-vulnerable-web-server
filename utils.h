#ifndef UTILS_H
#define UTILS_H

#include <cstddef>
#include <string>
#include <map>

std::string extract_header_value(const std::string& request, const std::string& header_name);
std::map<std::string, std::string> extract_query_parameters(const std::string& request);
bool extract_username_password(const std::string& authorization_header, std::string& username, std::string& password);
std::string url_decode(const std::string& str);

// Upper-bound size estimate for a %-escaped parameter value: counts
// every '%' as the start of a valid three-character %XX escape (one
// output byte), everything else 1:1. Stops at NUL, CR or LF. Used to
// size decode buffers before a decode pass.
size_t estimate_decoded_length(const char* s);

const char* get_cgi_helper_path();
#endif

