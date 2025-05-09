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
#include "token.h"


#define BUF_SIZE 256

// === Stub Implementations for Testing ===
// These simulate your db and logging behaviors for isolated unit tests

bool account_is_banned(const account_t *acct) {
    return acct->account_id == 2;
}

bool account_is_expired(const account_t *acct) {
    return acct->account_id == 3;
}

bool account_validate_password(const account_t *acct, const char *password) {
    return (acct->account_id == 1 && strcmp(password, "correctpw") == 0);
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
        printf(", start=%ld, expiry=%ld, token='%s'",
               (long)session->session_start,
               (long)session->expiration_time,
               session->session_token);
        free(session->session_token);
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
