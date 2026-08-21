// cgi_rules.h
//
// Backing store for the type-confusion challenge. AliasRule::target
// intentionally aliases ExecRule::callback in memory.
#ifndef DVWS_CGI_RULES_H
#define DVWS_CGI_RULES_H

#include <string>
#include <vector>

struct Rule {
    virtual ~Rule() = default;
    std::string path;
};

struct AliasRule : public Rule {
    // Overlaps with ExecRule::callback under a blind static_cast.
    char target[64];
};

struct ExecRule : public Rule {
    void (*callback)(const char*);
};

// Default CGI handler used when a rule is created via ?type=exec.
void default_cgi_handler(const char* request);

// Global registry (kept as a function-local static so we do not need
// to expose another loose-globals compilation unit).
std::vector<Rule*>& cgi_rules();

#endif
