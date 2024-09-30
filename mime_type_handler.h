//
// Created by sams on 08/06/2023.
//

#ifndef UNTITLED11_MIME_TYPE_HANDLER_H
#define UNTITLED11_MIME_TYPE_HANDLER_H


#include <stdio.h>
#include <stdbool.h>

char* get_content_type(const char* file_path);
void handle_php_file(FILE *file, int *client_socket, const char* response_header);
bool check_php_file(const char* file_path);

#endif //UNTITLED11_MIME_TYPE_HANDLER_H
