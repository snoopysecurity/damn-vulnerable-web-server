// cgi_rules.cpp
#include "cgi_rules.h"

#include <iostream>

void default_cgi_handler(const char* /*request*/) {
    std::cout << "Executing CGI handler..." << std::endl;
}

std::vector<Rule*>& cgi_rules() {
    static std::vector<Rule*> rules;
    return rules;
}
