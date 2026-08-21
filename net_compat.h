// net_compat.h
//
// Cross-platform flag for send() that suppresses SIGPIPE on client
// disconnect. Linux exposes MSG_NOSIGNAL; macOS/BSD do not (they use
// setsockopt SO_NOSIGPIPE on the socket instead). We also SIG_IGN
// SIGPIPE at startup in main(), so this is defence-in-depth.
#ifndef DVWS_NET_COMPAT_H
#define DVWS_NET_COMPAT_H

#include <sys/socket.h>

#ifdef MSG_NOSIGNAL
    #define DVWS_SEND_FLAGS MSG_NOSIGNAL
#else
    #define DVWS_SEND_FLAGS 0
#endif

#endif
