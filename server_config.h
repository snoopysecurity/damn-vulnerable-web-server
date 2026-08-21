// server_config.h
//
// Wraps what used to be the bare `SERVER_DIR` global in a named struct.
// The vulnerable 200-byte char array is *inside* the struct so the
// intentional argv-BOF primitive is preserved verbatim.
#ifndef DVWS_SERVER_CONFIG_H
#define DVWS_SERVER_CONFIG_H

struct ServerConfig {
    // Intentional CWE-121 target: unbounded strcpy(g_config.server_dir, argv[1]).
    // Keep this 200 bytes to preserve the challenge behavior.
    char server_dir[200];
    int  port;
    bool fuzz_mode;
};

extern ServerConfig g_config;

#endif
