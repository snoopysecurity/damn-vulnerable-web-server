//
// Created by sams on 08/06/2023.
//

#include "request_logger.h"

#include <stdio.h>
#include <time.h>

void log_request_response(const char *request, const char *response) {
    time_t current_time;
    char timestamp[20];
    struct tm *time_info;

    // Get current time
    current_time = time(NULL);
    time_info = localtime(&current_time);

    // Format timestamp
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", time_info);

    // Print timestamp, request, and response to the console
 //   printf("[%s] Request:\n%s\n\n", timestamp, request);
  //  printf("[%s] Response:\n%s\n\n", timestamp, response);

    // Open the log file in append mode
    FILE *log_file = fopen("/tmp/server.log", "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        return;
    }

    // Write timestamp, request, and response to the log file
    fprintf(log_file, "[%s] Request:\n%s\n\n", timestamp, request);
    fprintf(log_file, "[%s] Response:\n%s\n\n", timestamp, response);

    // Close the log file
    fclose(log_file);
}
