//
// Created by sams on 10/06/2023.
//
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#define MAX_REQUEST_SIZE 1024
#define ROOT_DIR "/tmp/html_files/"

#include "request_logger.h"


#include "error_handling.h"



void send_error_response(int client_socket, int status_code, const char* status_text, const char* requested_page) {
    char response_header[200];
    snprintf(response_header, sizeof(response_header), "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\n\r\n", status_code, status_text);

    // Construct the error message with the requested page name
    char error_message[200];
    snprintf(error_message, sizeof(error_message), "<html><body><h1>Error %d: %s</h1><p>Requested page: %s</p></body></html>", status_code, status_text, requested_page);

    // Send the response header
    if (send(client_socket, response_header, strlen(response_header), 0) < 0) {
        perror("Failed to send response header");
        return;
    }

    // Send the error message
    if (send(client_socket, error_message, strlen(error_message), 0) < 0) {
        perror("Failed to send error message");
        return;
    }
}

