// server_config.h
//
// Process-wide server configuration, set once from argv in main().
#ifndef DVWS_SERVER_CONFIG_H
#define DVWS_SERVER_CONFIG_H

struct ServerConfig {
    char server_dir[200];  // document root, copied from argv[1]
    int port;
    bool fuzz_mode;
};

extern ServerConfig g_config;

#endif
