#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>



#define MAX_REQUEST_SIZE 1024
#include "mime_type_handler.h"
#include "request_logger.h"
#include "error_handling.h"
#include "authentication.h"

char SERVER_DIR[200];

void send_authentication_required_response(int client_socket, const char* file_path, const char* request) {
    // Open the file
    printf("Requested filepath: %s\n", file_path);


    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        perror("Failed to open file");
        send_error_response(client_socket, 404, "Not Found", file_path);
        return;
    }
    printf("Serving file: %s\n", file_path); // Print the file path

    // Check if the file is a PHP file
    if (check_php_file(file_path)) {
        char response_header[200];
        snprintf(response_header, sizeof(response_header), "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");

        handle_php_file(file, &client_socket, response_header);
    } else {
        char* content_type = get_content_type(file_path);

        // Send the HTTP response headers
        char response_header[200];
        sprintf(response_header, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\n\r\n", content_type);
        //logging
        log_request_response(request, response_header);

        if (send(client_socket, response_header, strlen(response_header), 0) < 0) {
            perror("Failed to send response header");
            fclose(file);
            return;
        }

        // Read the file contents and send them to the client
        char file_buffer[1024];
        size_t bytes_read;
        while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
            if (send(client_socket, file_buffer, bytes_read, 0) < 0) {
                perror("Failed to send file");
                fclose(file);
                return;
            }
        }

        // Close the file
        fclose(file);
    }
    // Close the client socket after sending the response
    close(client_socket);
}


void handle_request(int client_socket, const char* request) {
   // printf("Received request:\n%s\n", request);

    // Parse the requested file path from the request header
    char* request_copy = strdup(request); // Make a copy of the request string
    char *path_start = strstr(request_copy, "GET /");
    if (path_start == NULL) {
        perror("Invalid request");
        close(client_socket);
        free(request_copy); // Free the allocated memory
        return;
    }

    char *path_end = strstr(path_start, " HTTP/");
    if (path_end == NULL) {
        perror("Invalid request");
        close(client_socket);
        free(request_copy); // Free the allocated memory
        return;
    }

    *path_end = '\0'; // Null-terminate the path
    char *path = path_start + 5; // Skip "GET /"

    char file_path[200];
    strcpy(file_path, SERVER_DIR);
    strcat(file_path, path);


    int authentication_result = perform_authentication(client_socket, file_path, request);

    free(request_copy); // Free the allocated memory

    if (authentication_result == 0) {
        // Authentication failed, return without sending the response
        close(client_socket);
        printf("Auth Failed\n");
        return;
    }
    printf("perform_authentication completed\n");
    send_authentication_required_response(client_socket, file_path, request);
    // Close the client socket after sending the response
    close(client_socket);
}


int main(int argc, char *argv[])  {
    if (argc < 3) {
        printf("Usage: %s SERVER_DIR PORT\n", argv[0]);
        printf("Please specify server directory and port number");
        return 1;
    }

    strcpy(SERVER_DIR, argv[1]);
    int port = atoi(argv[2]);

    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    socklen_t client_address_len = sizeof(client_address);

    // Create a socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        return 1;
    }

    // Set up the server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the specified IP and port
    if (bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Failed to bind socket");
        return 1;
    }

    // Listen for incoming connections
    if (listen(server_socket, 10) < 0) {
        perror("Failed to listen for connections");
        return 1;
    }

    printf("Server started on port %d\n", port);

    // Accept and handle incoming connections
    while (1) {
        printf("Waiting for request...\n");
        client_socket = accept(server_socket, (struct sockaddr *)&client_address, &client_address_len);
        if (client_socket < 0) {
            perror("Failed to accept connection");
            continue;
        }

        char request[MAX_REQUEST_SIZE];
        memset(request, 0, sizeof(request));

        // Receive the request from the client
        int recv_result = recv(client_socket, request, sizeof(request), 0);
        if (recv_result == 0) {
            printf("Client closed the connection.\n");
            close(client_socket);
            continue;
        } else if (recv_result < 0) {
            perror("Failed to receive request");
            close(client_socket);
            continue;
        }

        // Handle the request
        handle_request(client_socket, request);
    }

    // Close the server socket
    close(server_socket);

    return 0;
}

