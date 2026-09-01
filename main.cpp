// main.cpp
//
// Argument parsing, socket setup, and the accept loop. Routing lives
// in router.cpp and the handlers/ + http/ modules.
#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <csignal>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "http/response.h"
#include "router.h"
#include "server_config.h"
#include "thread_pool.h"

#define MAX_REQUEST_SIZE 1024
#define N_WORKER_THREADS 8

// Graceful shutdown: SIGTERM/SIGINT set a flag; the accept loop polls
// with a timeout so it re-checks the flag at least twice a second,
// then drains workers before exiting. Docker's STOPSIGNAL SIGTERM
// lands here.
static volatile sig_atomic_t g_shutdown_requested = 0;

static void request_shutdown(int) {
    g_shutdown_requested = 1;
}

// AFL++ persistent-mode hooks. Under afl-clang-fast these are provided
// as preprocessor macros; without AFL instrumentation the guarded block
// is compiled out and the harness falls back to a single-shot stdin read.

static int run_fuzz_mode() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    // Persistent mode: reuse the process across many test cases.
    // AFL++ recommends 1000-10000 iterations before recycling.
    __AFL_INIT();
    while (__AFL_LOOP(10000)) {
        char request[MAX_REQUEST_SIZE];
        memset(request, 0, sizeof(request));

        size_t total_read = 0;
        while (total_read < sizeof(request) - 1) {
            ssize_t bytes =
                read(STDIN_FILENO, request + total_read, sizeof(request) - 1 - total_read);
            if (bytes <= 0) break;
            total_read += bytes;
        }
        if (total_read == 0) continue;

        // Hand fd 0 in; response send()s fail harmlessly under the fuzzer.
        dispatch(0, request);
    }
    return 0;
#else
    // Non-AFL fallback: single-shot read from stdin.
    char request[MAX_REQUEST_SIZE];
    memset(request, 0, sizeof(request));

    size_t total_read = 0;
    while (total_read < sizeof(request) - 1) {
        ssize_t bytes = read(STDIN_FILENO, request + total_read, sizeof(request) - 1 - total_read);
        if (bytes <= 0) break;
        total_read += bytes;
    }

    if (total_read > 0) {
        dispatch(0, request);
    }
    return 0;
#endif
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " SERVER_DIR PORT [--fuzz]" << std::endl;
        std::cout << "Please specify server directory and port number" << std::endl;
        return 1;
    }

    // Copy the server directory argument into the fixed-size field of
    // the global config.
    strcpy(g_config.server_dir, argv[1]);
    g_config.port = atoi(argv[2]);
    g_config.fuzz_mode = (argc > 3 && strcmp(argv[3], "--fuzz") == 0);

    if (g_config.fuzz_mode) {
        return run_fuzz_mode();
    }
    int port = g_config.port;

    // A client disconnecting mid-response would otherwise kill the
    // server via SIGPIPE. Handlers that care about robust delivery
    // should additionally pass MSG_NOSIGNAL to their send() calls on
    // Linux.
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, request_shutdown);
    signal(SIGINT, request_shutdown);

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Failed to set SO_REUSEADDR");
    }

    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Failed to bind socket");
        return 1;
    }

    if (listen(server_socket, 10) < 0) {
        perror("Failed to listen for connections");
        return 1;
    }

    // Startup banner.
    std::cout << http::kServerBanner << " (damn-vulnerable-web-server) starting up\n"
              << "  docroot:   " << g_config.server_dir << "\n"
              << "  listening: 0.0.0.0:" << port << "\n"
              << "  workers:   " << N_WORKER_THREADS << "\n"
              << "ready to accept connections" << std::endl;

    ThreadPool pool(N_WORKER_THREADS);

    while (!g_shutdown_requested) {
        // Poll with a timeout so a shutdown request is noticed even while
        // no connections are arriving (signal() installs the handler with
        // SA_RESTART, so we cannot rely on EINTR waking us).
        struct pollfd pfd = {server_socket, POLLIN, 0};
        int ready = poll(&pfd, 1, 500);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("Failed to poll listen socket");
            continue;
        }
        if (ready == 0) continue;  // timeout; loop re-checks the flag

        struct sockaddr_in client_address{};
        socklen_t client_address_len = sizeof(client_address);
        int client_socket =
            accept(server_socket, (struct sockaddr*)&client_address, &client_address_len);
        if (client_socket < 0) {
            perror("Failed to accept connection");
            continue;
        }

        // Off-load to a worker. The worker owns closing client_socket.
        pool.submit([client_socket] {
            char request[MAX_REQUEST_SIZE];
            memset(request, 0, sizeof(request));
            // Leave one byte for the trailing NUL so parse()'s
            // C-string operations stay in bounds when the client sends
            // >= MAX_REQUEST_SIZE bytes.
            int recv_result = recv(client_socket, request, sizeof(request) - 1, 0);
            if (recv_result <= 0) {
                close(client_socket);
                return;
            }
            dispatch(client_socket, request);
        });
    }

    std::cout << "shutdown requested: closing the listen socket and draining "
                 "workers"
              << std::endl;
    close(server_socket);
    return 0;
}
