// dvws_cgi_helper.cpp
//
// Bundled native CGI helper for CH-06. The server stages a copy of
// this executable at a predictable /tmp path and executes it per
// request on /cgi-helper (see mime_type_handler.cpp). It replaces the
// old php-cli bridge: no interpreter, no script syntax, just a tiny
// native binary that speaks enough CGI to be observable.
//
// Its whole job is to print a CGI-style response -- a header block, a
// blank line, then a short body. The PID/UID lines are harmless
// context: they prove which process and user actually ran, which is
// exactly what matters when the temp-file race is won.
#include <sys/types.h>
#include <unistd.h>
#include <cstdio>

int main() {
    std::printf("Content-Type: text/plain\r\n");
    std::printf("\r\n");
    std::printf("DVWS native CGI helper\n");
    std::printf("pid=%d uid=%d\n", static_cast<int>(getpid()), static_cast<int>(getuid()));
    return 0;
}
