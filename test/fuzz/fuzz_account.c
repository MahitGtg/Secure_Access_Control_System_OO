// test/fuzz/fuzz_login.c
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "login.h"
#include "db.h"
#include "logging.h"

// Stub for log_message
void log_message(log_level_t level, const char *fmt, ...)
{
    // Do nothing during fuzzing
    (void)level;
    (void)fmt;
}

// Stub for account lookup that always returns a valid account
bool account_lookup_by_userid(const char *userid, account_t *result)
{
    if (!userid || !result)
        return false;

    // Initialize with default values
    memset(result, 0, sizeof(account_t));

    // Set some data for testing
    result->account_id = 1;
    strncpy(result->userid, userid, USER_ID_LENGTH - 1);

    // Hardcode a known password hash if it's the admin user
    if (strcmp(userid, "admin") == 0)
    {
        // This would be a real Argon2id hash in production
        strcpy(result->password_hash, "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHRzYWx0$hash");
    }

    // Return success
    return true;
}

// For libfuzzer
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Need minimum data to fuzz effectively
    if (size < 8)
        return 0;

    // Prepare null-terminated strings
    char *username = (char *)malloc(size / 2 + 1);
    char *password = (char *)malloc(size / 2 + 1);

    if (!username || !password)
    {
        free(username);
        free(password);
        return 0;
    }

    // Split data between username and password, ensuring we don't overflow
    size_t username_len = size / 2;
    size_t password_len = size - username_len;

    // Ensure we don't write past the allocated buffers
    memcpy(username, data, username_len < size / 2 + 1 ? username_len : size / 2);
    username[size / 2] = '\0';

    memcpy(password, data + username_len, password_len < size / 2 + 1 ? password_len : size / 2);
    password[size / 2] = '\0';

    // Create a pipe for client_output_fd
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0)
    {
        free(username);
        free(password);
        return 0;
    }

    // Generate an IP address from fuzzer data
    ip4_addr_t ip = 0;
    if (size >= 4)
    {
        ip = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    }

    // Create a session struct
    login_session_data_t session = {0};

    // Call handle_login
    handle_login(username, password, ip, time(NULL), pipe_fds[1], &session);

    // Clean up
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    free(username);
    free(password);

    return 0;
}
