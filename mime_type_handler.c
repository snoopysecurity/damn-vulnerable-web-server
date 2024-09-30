//
// Created by sams on 08/06/2023.
//

#include "mime_type_handler.h"
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


char* get_content_type(const char* file_path) {
    char* content_type = "text/plain"; // Default content type
    char* extension = strrchr(file_path, '.');
    if (extension != NULL) {
        if (strcmp(extension, ".html") == 0) {
            content_type = "text/html";
        } else if (strcmp(extension, ".jpeg") == 0 || strcmp(extension, ".jpg") == 0) {
            content_type = "image/jpeg";
        } else if (strcmp(extension, ".png") == 0) {
            content_type = "image/png";
        } else if (strcmp(extension, ".gif") == 0) {
            content_type = "image/gif";
        } else if (strcmp(extension, ".txt") == 0) {
            content_type = "text/plain";
        } else if (strcmp(extension, ".css") == 0) {
            content_type = "text/css";
        } else if (strcmp(extension, ".js") == 0) {
            content_type = "application/javascript";
        } else if (strcmp(extension, ".json") == 0) {
            content_type = "application/json";
        } else if (strcmp(extension, ".xml") == 0) {
            content_type = "application/xml";
        } else if (strcmp(extension, ".pdf") == 0) {
            content_type = "application/pdf";
        } else if (strcmp(extension, ".zip") == 0) {
            content_type = "application/zip";
        }
        // Add more cases for other file types if needed
    }


    return content_type;
}

bool check_php_file(const char* file_path) {
    // Get the file extension
    const char* extension = strrchr(file_path, '.');
    if (extension != NULL) {
        // Compare the file extension to ".php"
        if (strcmp(extension, ".php") == 0) {
            return true; // It's a PHP file
        }
    }
    return false; // Not a PHP file
}

void handle_php_file(FILE *file, int *client_socket, const char* response_header) {
    // Get the process ID
    pid_t pid = getpid();

    // Generate a unique temporary file name using the process ID
    char temp_file_path[200];
    snprintf(temp_file_path, sizeof(temp_file_path), "/tmp/php_script_%d.php", pid);

    // Open the temporary file for writing
    FILE *temp_file = fopen(temp_file_path, "w");
    if (temp_file == NULL) {
        perror("Failed to create temporary file");
        return;
    }

    // Write the contents of the PHP script to the temporary file
    char file_buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
        fwrite(file_buffer, 1, bytes_read, temp_file);
    }

    // Close the temporary file
    fclose(temp_file);

    // Get the path to the PHP interpreter
    char interpreter_path[200] = "/opt/homebrew/bin/php";

    // Construct the command to execute the PHP script
    char command[256];
    snprintf(command, sizeof(command), "%s %s", interpreter_path, temp_file_path);

    // Create a pipe for communication with the PHP interpreter
    FILE *php_output = popen(command, "r");
    if (php_output == NULL) {
        perror("Failed to execute PHP script");
        return;
    }

    // Send the HTTP response header
    if (send(*client_socket, response_header, strlen(response_header), 0) < 0) {
        perror("Failed to send response header");
        fclose(file);
        return;
    }

    // Read the output from the PHP interpreter and send it to the client
    char php_buffer[1024];
    size_t php_bytes_read;
    while ((php_bytes_read = fread(php_buffer, 1, sizeof(php_buffer), php_output)) > 0) {
        if (send(*client_socket, php_buffer, php_bytes_read, 0) < 0) {
            perror("Failed to send PHP output");
            return;
        }
    }

    // Close the file
    fclose(file);

    // Remove the temporary file
    remove(temp_file_path);
}






