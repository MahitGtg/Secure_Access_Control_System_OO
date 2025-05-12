/**
 * login.c
 *
 * Implements secure user login handling with proper validation, error handling,
 * and mitigation against common security issues.
 *
 * Preconditions for all functions in this file:
 *   - String arguments must be valid, null-terminated (caller responsibility).
 *   - Pointer arguments must be non-NULL.
 *   - File descriptor arguments must be valid and open for writing.
 */

#include "login.h"   // handle_login declaration
#include "db.h"      // account_lookup_by_userid, account_t
#include "logging.h" // log_message, log levels
#include "token.h"   // generate_session_token
#include <unistd.h>  // write()
#include <fcntl.h>   // fcntl() for FD validation
#include <errno.h>   // errno
#include <string.h>  // strlen(), strncpy()
#include <time.h>    // time_t
#include "banned.h"

#define SESSION_DURATION (3600) // 1 hour
#define MAX_USERNAME_LEN (256)  // Max bytes to log for username

/**
 * fd_is_valid
 *
 * Checks whether a given file descriptor is valid and open for writing.
 *
 * Preconditions:
 *   - fd may be any integer; function handles invalid values gracefully.
 *
 * Parameters:
 *   - fd: the file descriptor to check
 *
 * Returns:
 *   - true if fd >= 0 and fcntl(fd, F_GETFL) succeeds (not EBADF)
 *   - false otherwise
 */
static bool fd_is_valid(int fd)
{
  if (fd < 0)
    return false;

  // Check if fd exists
  int flags = fcntl(fd, F_GETFL);
  if (flags == -1)
    return false;

  // Check if fd is writable
  if ((flags & O_WRONLY) == 0 && (flags & O_RDWR) == 0)
  {
    return false;
  }

  return true;
}

/**
 * handle_login
 *
 * Authenticates a user and initializes a login session.
 *
 * Preconditions:
 *   - username and password must be non-NULL, valid, null-terminated strings.
 *   - session must be a non-NULL pointer to login_session_data_t.
 *   - client_output_fd must be a valid file descriptor open for writing.
 *
 * Parameters:
 *   - username          : the user's login identifier
 *   - password          : the plaintext password to verify
 *   - client_ip         : IP address of the client
 *   - login_time        : timestamp of the login attempt
 *   - client_output_fd  : file descriptor to write messages to the client
 *   - session           : pointer to struct to populate on successful login
 *
 * Returns:
 *   - LOGIN_SUCCESS on successful authentication
 *   - LOGIN_FAIL_USER_NOT_FOUND   if username is not in the system
 *   - LOGIN_FAIL_BAD_PASSWORD     if password does not match
 *   - LOGIN_FAIL_ACCOUNT_BANNED   if the account is banned
 *   - LOGIN_FAIL_ACCOUNT_EXPIRED  if the account has expired
 *   - LOGIN_FAIL_IP_BANNED        if too many failures (>10) occurred
 *   - LOGIN_FAIL_INTERNAL_ERROR   on other errors (e.g., invalid parameters)
 */
login_result_t handle_login(const char *username,
                            const char *password,
                            ip4_addr_t client_ip,
                            time_t login_time,
                            int client_output_fd,
                            login_session_data_t *session)
{
  // 1) Preconditions
  if (!username || !password || !session)
  {
    log_message(LOG_ERROR, "handle_login: null parameter");
    return LOGIN_FAIL_INTERNAL_ERROR;
  }
  if (!fd_is_valid(client_output_fd))
  {
    log_message(LOG_ERROR, "handle_login: invalid client_output_fd=%d", client_output_fd);
    return LOGIN_FAIL_INTERNAL_ERROR;
  }

  // 2) Safe truncation for logging username
  char safe_user[MAX_USERNAME_LEN + 1];
  strncpy(safe_user, username, MAX_USERNAME_LEN);
  safe_user[MAX_USERNAME_LEN] = '\0';

  // 3) Lookup account
  account_t acct;
  bool user_exists = account_lookup_by_userid(username, &acct);

  // 4) Constant-time password check
  bool password_ok;
  if (user_exists)
  {
    password_ok = account_validate_password(&acct, password);
  }
  else
  {
    account_t dummy = {0};
    password_ok = account_validate_password(&dummy, password);
  }

  // 5) Handle invalid credentials
  if (!user_exists || !password_ok)
  {
    log_message(LOG_INFO, "Login failed: invalid credentials");
    const char *msg = "Invalid username or password\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    if (user_exists)
      account_record_login_failure(&acct);
    return user_exists ? LOGIN_FAIL_BAD_PASSWORD : LOGIN_FAIL_USER_NOT_FOUND;
  }

  // 6) Snapshot for race-condition mitigation
  bool is_banned = account_is_banned(&acct);
  bool is_expired = account_is_expired(&acct);
  unsigned int fail_count = acct.login_fail_count;

  // 7) Check banned status
  if (is_banned)
  {
    log_message(LOG_WARN, "Login attempt on banned account: %s", safe_user);
    const char *msg = "Account banned. Contact support.\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    return LOGIN_FAIL_ACCOUNT_BANNED;
  }

  // 8) Check expired status
  if (is_expired)
  {
    log_message(LOG_WARN, "Login attempt on expired account: %s", safe_user);
    const char *msg = "Account expired. Please renew subscription.\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    return LOGIN_FAIL_ACCOUNT_EXPIRED;
  }

  // 9) Check failure threshold
  if (fail_count > 10)
  {
    log_message(LOG_WARN, "Account locked (too many failures): %s", safe_user);
    const char *msg = "Too many failed attempts. Try again later.\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    return LOGIN_FAIL_IP_BANNED;
  }

  // 10) Record success and generate session token
  account_record_login_success(&acct, client_ip);
  session->account_id = (int)acct.account_id;
  session->session_start = login_time;
  session->expiration_time = login_time + SESSION_DURATION;
  session->session_token = generate_session_token();

  // 11) Notify client and log success
  log_message(LOG_INFO, "User logged in successfully: id=%d", acct.account_id);
  const char *msg_ok = "Login successful\n";
  ssize_t nw = write(client_output_fd, msg_ok, strlen(msg_ok));
  if (nw < 0)
    log_message(LOG_ERROR, "write() failed: %s", strerror(errno));

  return LOGIN_SUCCESS;
}
