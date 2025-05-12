#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>   
#include "login.h"
#include "db.h"
#include "logging.h"

#define BUF_SIZE 256

// === Stub Implementations for Testing ===
// These are weak symbols so they won't conflict with real implementations

// Stub functions with __attribute__((weak)) to avoid conflicts with real implementations
__attribute__((weak)) bool account_is_banned(const account_t *acct) {
    // User ID 2 is a banned account for testing
    return acct->account_id == 2;
}

__attribute__((weak)) bool account_is_expired(const account_t *acct) {
    // User ID 3 is an expired account for testing
    return acct->account_id == 3;
}

__attribute__((weak)) bool account_validate_password(const account_t *acct, const char *password) {
    // User ID 1 has password "correctpw"
    return (acct->account_id == 1 && strcmp(password, "correctpw") == 0);
}

__attribute__((weak)) void account_record_login_success(account_t *acc, ip4_addr_t ip) {
    // Just a stub - does nothing
    (void)acc;
    (void)ip;
}

__attribute__((weak)) void account_record_login_failure(account_t *acc) {
    // Just a stub - does nothing
    (void)acc;
}

__attribute__((weak)) bool account_lookup_by_userid(const char *userid, account_t *result) {
    if (strcmp(userid, "testuser") == 0) {
        // Valid user for testing
        result->account_id = 1;
        strncpy(result->userid, "testuser", USER_ID_LENGTH - 1);
        result->login_fail_count = 0;
        return true;
    } else if (strcmp(userid, "banned_user") == 0) {
        // Banned user for testing
        result->account_id = 2;
        strncpy(result->userid, "banned_user", USER_ID_LENGTH - 1);
        return true;
    } else if (strcmp(userid, "expired_user") == 0) {
        // Expired user for testing
        result->account_id = 3;
        strncpy(result->userid, "expired_user", USER_ID_LENGTH - 1);
        return true;
    } else if (strcmp(userid, "locked_user") == 0) {
        // Locked user for testing (too many failed attempts)
        result->account_id = 4;
        strncpy(result->userid, "locked_user", USER_ID_LENGTH - 1);
        result->login_fail_count = 11; // Over threshold (10)
        return true;
    }
    return false;
}

// Helper: run an individual test and capture output
static void run_test(const char *name,
                     const char *username,
                     const char *password,
                     ip4_addr_t client_ip,
                     time_t now,
                     int write_fd,
                     int read_fd,
                     login_session_data_t *session) {
    char buf[BUF_SIZE] = {0};
    login_result_t res = handle_login(username, password, client_ip, now, write_fd, session);
    ssize_t n = read(read_fd, buf, BUF_SIZE - 1);
    if (n > 0) buf[n] = '\0';
    printf("%s: res=%d, msg='%s'", name, res, buf);
    if (res == LOGIN_SUCCESS) {
        printf(", start=%ld, expiry=%ld", 
               (long)session->session_start,
               (long)session->expiration_time);
    }
    printf("\n");
}

int main(void) {
    int fds[2];
    if (pipe(fds) < 0) {
        perror("pipe");
        return 1;
    }

    time_t now = time(NULL);
    login_session_data_t session;

    // Run tests for different login scenarios
    run_test("User Not Found",   "no_user",      "pw",        0, now, fds[1], fds[0], &session);
    run_test("Banned Account",   "banned_user",  "pw",        0, now, fds[1], fds[0], &session);
    run_test("Expired Account",  "expired_user", "pw",        0, now, fds[1], fds[0], &session);
    run_test("Locked Account",   "locked_user",  "pw",        0, now, fds[1], fds[0], &session);
    run_test("Bad Password",     "testuser",    "wrongpw",   0, now, fds[1], fds[0], &session);
    run_test("Successful Login", "testuser",    "correctpw", 0, now, fds[1], fds[0], &session);

    close(fds[0]);
    close(fds[1]);
    return 0;
}