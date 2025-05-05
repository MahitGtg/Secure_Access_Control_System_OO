#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "login.h"
#include "db.h"
#include "logging.h"

#define BUF_SIZE 256

// === Stub Implementations for Testing ===

// Simulates database lookup by userid
bool account_lookup_by_userid(const char *username, account_t *acct) {
    if (strcmp(username, "testuser") == 0) {
        acct->account_id = 1;
        acct->login_fail_count = 0;
        return true;
    } else if (strcmp(username, "banned_user") == 0) {
        acct->account_id = 2;
        acct->login_fail_count = 0;
        return true;
    } else if (strcmp(username, "expired_user") == 0) {
        acct->account_id = 3;
        acct->login_fail_count = 0;
        return true;
    } else if (strcmp(username, "locked_user") == 0) {
        acct->account_id = 4;
        acct->login_fail_count = 11;
        return true;
    }
    return false;
}

// Simulates ban status
bool account_is_banned(const account_t *acct) {
    return acct->account_id == 2;
}

// Simulates expiry status
bool account_is_expired(const account_t *acct) {
    return acct->account_id == 3;
}

// Simulates password validation
bool account_validate_password(const account_t *acct, const char *password) {
    return (acct->account_id == 1 && strcmp(password, "correctpw") == 0);
}

// Recording login failure: no-op for test
void account_record_login_failure(account_t *acct) {}

// Recording login success: no-op for test
void account_record_login_success(account_t *acct, ip4_addr_t client_ip) {}

// Simple logger stub
void log_message(log_level_t level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

// Helper to run a single test scenario
enum { SUCCESS = 0, FAIL };
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
    printf("%s: res=%d, msg='%s'\n", name, res, buf);
}

int main(void) {
    int fds[2];
    if (pipe(fds) < 0) {
        perror("pipe");
        return FAIL;
    }

    time_t now = time(NULL);
    login_session_data_t session;

    run_test("User Not Found",   "no_user",      "pw",        0, now, fds[1], fds[0], &session);
    run_test("Banned Account",   "banned_user",  "pw",        0, now, fds[1], fds[0], &session);
    run_test("Expired Account",  "expired_user", "pw",        0, now, fds[1], fds[0], &session);
    run_test("Locked Account",   "locked_user",  "pw",        0, now, fds[1], fds[0], &session);
    run_test("Bad Password",     "testuser",    "wrongpw",  0, now, fds[1], fds[0], &session);
    run_test("Successful Login", "testuser",    "correctpw",0, now, fds[1], fds[0], &session);

    close(fds[0]);
    close(fds[1]);
    return SUCCESS;
}
