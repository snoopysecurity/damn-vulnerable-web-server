//
// Created by sams on 11/06/2023.
//
// authentication.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#define MAX_USERNAME_LENGTH 100
#define MAX_PASSWORD_LENGTH 100
#define MAX_REQUEST_SIZE 8000
#include <string.h>
#include <ctype.h>
#include "base64.h"
#include <stdbool.h>
#include "authentication.h"


const char* extract_header_value(const char* request, const char* header_name) {
    size_t header_name_length = strlen(header_name);
    // Trim leading whitespace characters
    while (isspace((unsigned char)header_name[0])) {
        header_name++;
        header_name_length--;
    }
    // Trim trailing whitespace characters
    while (header_name_length > 0 && isspace((unsigned char)header_name[header_name_length - 1])) {
        header_name_length--;
    }
    const char* line = strtok((char*)request, "\r\n");
    while (line != NULL) {
        //printf("%s\n", line);
        // Perform case-insensitive comparison
        if (strncasecmp(line, header_name, header_name_length) == 0) {
            const char* header_value_start = line + header_name_length;
            // Skip leading spaces
            while (*header_value_start == ' ') {
                header_value_start++;
            }
            return header_value_start;
        }

        line = strtok(NULL, "\r\n");
    }

    printf("Header not found: %s\n", header_name);
    return NULL; // Header not found
}


// Function to check if the provided username and password are valid
int authenticate(const char* username, const char* password) {
    // Check if the provided username and password are valid for login
    if (strcmp(username, "admin") == 0 && strcmp(password, "admin") == 0) {
        return 1; // Successful login
    } else {
        return 0; // Login failed
    }
}



void send_basic_auth_prompt(int client_socket) {
    const char* header = "HTTP/1.1 401 Unauthorized\r\n"
                         "WWW-Authenticate: Basic realm=\"Restricted\"\r\n"
                         "Content-Length: 0\r\n"
                         "Custom-Header: SomeValue\r\n" // Add a custom header
                         "\r\n";

    if (send(client_socket, header, strlen(header), 0) < 0) {
        perror("Failed to send response header");
        return; // Return if failed to send
    }
}

bool extract_username_password(const char* authorization_header, char* username, char* password) {
    // Move the pointer past "Basic "
    authorization_header += strlen("Basic ");

    // Decode the base64-encoded credentials
    size_t decode_length = 0;
    unsigned char* decoded_credentials = base64_decode(authorization_header, strlen(authorization_header), &decode_length);

    if (decoded_credentials == NULL || decode_length == 0) {
        perror("Failed to decode credentials");
        return false;
    }

    // Null-terminate the decoded credentials
    decoded_credentials[decode_length] = '\0';

    // Extract the username and password from the decoded credentials
    char* colon = strchr((char*)decoded_credentials, ':');
    if (colon == NULL) {
        perror("Invalid credentials format");
        free(decoded_credentials);
        return false;
    }

    // Null-terminate the username and copy it to the username variable
    *colon = '\0';
    strcpy(username, (char*)decoded_credentials);

    // Copy the password to the password variable, excluding the ':' character
    strcpy(password, colon + 1);

    // Cleanup the decoded credentials
    free(decoded_credentials);

    return true;
}



// Function to perform authentication for a given file path
int perform_authentication(int client_socket, const char* file_path, const char* original_request) {
    char request[MAX_REQUEST_SIZE];
    strcpy(request, original_request);

    const char* filename = strrchr(file_path, '/');
    if (filename != NULL) {
        filename++; // Move past the '/' character
    } else {
        filename = file_path; // No '/' character found, use the entire filepath as the filename
    }

    // Check if the requested file path requires authentication
    if (strstr(filename, "echo.php") != NULL || strstr(filename, "g.php") != NULL) {
        // Extract the "Authorization" header value
        const char* authorization_header = extract_header_value(request, "Authorization:");

        if (authorization_header == NULL) {
            // Send authentication prompt
            send_basic_auth_prompt(client_socket);
            return 0; // Authentication failed
        }
        char username[MAX_USERNAME_LENGTH];
        char password[MAX_PASSWORD_LENGTH];

        if (!extract_username_password(authorization_header, username, password)) {
            // Send authentication prompt
            send_basic_auth_prompt(client_socket);
            return 0; // Authentication failed
        }

        if (authenticate(username, password)) {
            return 1; // Authentication successful
        } else {
            // Send authentication prompt
            send_basic_auth_prompt(client_socket);
            return 0; // Authentication failed
        }
    }

    return 1; // No authentication required for other files
}








