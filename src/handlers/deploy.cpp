// handlers/deploy.cpp
//
// Quick Deploy feature - upload ZIP archives containing static sites.
//
// CH-14: Zip Slip (CWE-22) - The extraction loop constructs output
// paths by concatenating the deployment directory with ZIP entry names
// without validation. Malicious entries like "../../index.html" escape
// the deployment directory and overwrite arbitrary files.

#include "deploy.h"

#include "../http/response.h"
#include "../server_config.h"

#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#include "miniz.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace handlers {

namespace {

// Ensure the deployment directory exists.
void ensure_deploy_directory(const char* path) {
    struct stat st{};
    if (stat(path, &st) == -1) {
        mkdir(path, 0755);
    }
}

// Write data to a file, creating parent directories if needed.
bool write_file(const char* path, const void* data, size_t size) {
    // Extract directory path and create it
    std::string dir_path(path);
    size_t last_slash = dir_path.find_last_of('/');
    if (last_slash != std::string::npos) {
        std::string dir = dir_path.substr(0, last_slash);
        // Create directory recursively (simplified - assumes parent exists)
        mkdir(dir.c_str(), 0755);
    }

    FILE* f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "[deploy] Failed to create file: %s\n", path);
        return false;
    }
    
    size_t written = fwrite(data, 1, size, f);
    fclose(f);
    
    if (written != size) {
        fprintf(stderr, "[deploy] Incomplete write to: %s\n", path);
        return false;
    }
    
    fprintf(stderr, "[deploy] Extracted: %s (%zu bytes)\n", path, size);
    return true;
}

}  // namespace

void deploy_site(int client_socket, const HttpRequest& req) {
    fprintf(stderr, "[deploy] Handler called! Method: %s\n", req.method.c_str());
    const bool head_only = (req.method == "HEAD");
    
    // Read Content-Length header
    std::string content_length_str = req.header("Content-Length");
    fprintf(stderr, "[deploy] Content-Length: %s\n", content_length_str.c_str());
    if (content_length_str.empty()) {
        http::send_json(client_socket,
                       "{\"status\": \"error\", \"message\": \"Missing Content-Length.\"}", 
                       "", head_only);
        return;
    }
    
    size_t content_len = (size_t)strtoull(content_length_str.c_str(), nullptr, 10);
    if (content_len == 0 || content_len > 10 * 1024 * 1024) {  // 10MB max
        http::send_json(client_socket,
                       "{\"status\": \"error\", \"message\": \"Invalid content length.\"}", 
                       "", head_only);
        return;
    }
    
    // Find where body starts in the request buffer
    const char* body_start = strstr(req.raw, "\r\n\r\n");
    if (!body_start) {
        http::send_json(client_socket,
                       "{\"status\": \"error\", \"message\": \"Malformed request - no body delimiter.\"}", 
                       "", head_only);
        return;
    }
    body_start += 4;  // Skip \r\n\r\n
    
    // Allocate buffer for ZIP data
    char* zip_data = (char*)malloc(content_len);
    if (!zip_data) {
        http::send_json(client_socket,
                       "{\"status\": \"error\", \"message\": \"Memory allocation failed.\"}", 
                       "", head_only);
        return;
    }
    
    // For simplicity: just copy from body_start
    // The initial recv() in main.cpp reads up to 1023 bytes which includes headers + body.
    // For small POSTs (< ~900 bytes total), the entire body is already in req.raw.
    // For larger ones, this is vulnerable as-written but demonstrates the Zip Slip bug.
    memcpy(zip_data, body_start, content_len);
    
    // Build deployment directory path
    char deploy_dir[512];
    snprintf(deploy_dir, sizeof(deploy_dir), "%s/deploy", g_config.server_dir);
    ensure_deploy_directory(deploy_dir);
    
    // Initialize miniz ZIP reader
    mz_zip_archive zip{};
    
    fprintf(stderr, "[deploy] Initializing ZIP reader with %zu bytes\n", content_len);
    fprintf(stderr, "[deploy] First 4 bytes: %02x %02x %02x %02x\n", 
            (unsigned char)zip_data[0], (unsigned char)zip_data[1],
            (unsigned char)zip_data[2], (unsigned char)zip_data[3]);
    
    mz_bool status = mz_zip_reader_init_mem(&zip, zip_data, content_len, 0);
    if (!status) {
        free(zip_data);
        http::send_json(client_socket,
                       "{\"status\": \"error\", \"message\": \"Invalid ZIP archive.\"}", 
                       "", head_only);
        return;
    }
    
    int num_files = mz_zip_reader_get_num_files(&zip);
    int extracted_count = 0;
    
    fprintf(stderr, "[deploy] Processing ZIP with %d entries...\n", num_files);
    
    // CH-14 VULNERABILITY: Extract each file without path validation
    for (int i = 0; i < num_files; i++) {
        // Get filename
        char filename[512];
        mz_uint filename_len = mz_zip_reader_get_filename(&zip, i, filename, sizeof(filename));
        if (filename_len == 0) {
            fprintf(stderr, "[deploy] Failed to get filename for entry %d\n", i);
            continue;
        }
        
        // Skip directories (filenames ending with /)
        if (filename[filename_len - 1] == '/') {
            continue;
        }
        
        // VULNERABLE: Construct output path without sanitizing entry name
        // Malicious ZIP entries like "../../index.html" will escape
        // the deployment directory and write to arbitrary locations.
        char output_path[1024];
        snprintf(output_path, sizeof(output_path), "%s/%s", 
                 deploy_dir, filename);
        
        fprintf(stderr, "[deploy] Entry %d: '%s' -> '%s'\n", i, filename, output_path);
        
        // No canonicalization! No containment check! Classic Zip Slip.
        // A filename like "../../etc/passwd" or "../../index.html"
        // will be written to that exact path relative to deploy_dir.
        
        // Extract file data
        size_t uncompressed_size;
        void* file_data = mz_zip_reader_extract_to_heap(&zip, i, &uncompressed_size, 0);
        
        if (file_data) {
            if (write_file(output_path, file_data, uncompressed_size)) {
                extracted_count++;
            }
            mz_free(file_data);
        }
    }
    
    mz_zip_reader_end(&zip);
    free(zip_data);
    
    // Return success response
    char response[256];
    snprintf(response, sizeof(response),
             "{\"status\": \"ok\", \"message\": \"Deployed %d files to /deploy/\"}", 
             extracted_count);
    http::send_json(client_socket, response, "", head_only);
    
    fprintf(stderr, "[deploy] Deployment complete: %d files extracted\n", extracted_count);
}

}  // namespace handlers
