/**
 * login.c
 *
 * Implements secure user login handling with proper validation, error handling,
 * and mitigation against common security issues.
 */

#include "login.h"   // handle_login declaration
#include "db.h"      // account_lookup_by_userid, account_t
#include "logging.h" // log_message, log levels
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
 */
login_result_t handle_login(const char *username,
                            const char *password,
                            ip4_addr_t client_ip,
                            time_t login_time,
                            int client_output_fd,
                            login_session_data_t *session)
{
  // 1) Parameter validation (we can keep some critical checks)
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

  if (!user_exists)
  {
    log_message(LOG_INFO, "Login failed: user '%s' not found", safe_user);
    const char *msg = "Invalid username or password\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    return LOGIN_FAIL_USER_NOT_FOUND;
  }

  // 4) Check password
  bool password_ok = account_validate_password(&acct, password);
  if (!password_ok)
  {
    log_message(LOG_INFO, "Login failed: incorrect password for user '%s'", safe_user);
    const char *msg = "Invalid username or password\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    account_record_login_failure(&acct);
    return LOGIN_FAIL_BAD_PASSWORD;
  }

  // 5) Check account status
  if (account_is_banned(&acct))
  {
    log_message(LOG_WARN, "Login attempt on banned account: %s", safe_user);
    const char *msg = "Account banned. Contact support.\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    return LOGIN_FAIL_ACCOUNT_BANNED;
  }

  if (account_is_expired(&acct))
  {
    log_message(LOG_WARN, "Login attempt on expired account: %s", safe_user);
    const char *msg = "Account expired. Please renew subscription.\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    return LOGIN_FAIL_ACCOUNT_EXPIRED;
  }

  // 6) Check consecutive login failures
  if (acct.login_fail_count > 10)
  {
    log_message(LOG_WARN, "Account locked (too many failures): %s", safe_user);
    const char *msg = "Too many failed attempts. Try again later.\n";
    ssize_t nw = write(client_output_fd, msg, strlen(msg));
    if (nw < 0)
      log_message(LOG_ERROR, "write() failed: %s", strerror(errno));
    return LOGIN_FAIL_IP_BANNED;
  }

  // 7) Record login success
  account_record_login_success(&acct, client_ip);

  // 8) Populate session data
  session->account_id = (int)acct.account_id;
  session->session_start = login_time;
  session->expiration_time = login_time + SESSION_DURATION;

  // 9) Notify client and log success
  log_message(LOG_INFO, "User '%s' logged in successfully", safe_user);
  const char *msg_ok = "Login successful\n";
  ssize_t nw = write(client_output_fd, msg_ok, strlen(msg_ok));
  if (nw < 0)
    log_message(LOG_ERROR, "write() failed: %s", strerror(errno));

  return LOGIN_SUCCESS;
}