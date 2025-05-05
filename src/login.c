#include "login.h"
#include "db.h"   
#include "logging.h"
#include <unistd.h>
#include <time.h>
#include <string.h>

/** Default session duration in seconds (1 hour) */
#define SESSION_DURATION (3600)


login_result_t handle_login(const char *username,
  const char *password,
  ip4_addr_t client_ip,
  time_t login_time,
  int client_output_fd,
  login_session_data_t *session) {
// 1) Preconditions: ensure required pointers are valid
if (!username || !password || !session) {
log_message(LOG_ERROR, "handle_login: null parameter");
const char *msg = "Internal server error\n";
write(client_output_fd, msg, strlen(msg));
return LOGIN_FAIL_INTERNAL_ERROR;
}

// 2) Lookup user account
account_t acct;
if (!account_lookup_by_userid(username, &acct)) {
log_message(LOG_INFO, "Login failed: user not found: %s", username);
const char *msg = "Invalid username or password\n";
write(client_output_fd, msg, strlen(msg));
return LOGIN_FAIL_USER_NOT_FOUND;
}

// 3) Check if account is banned
if (account_is_banned(&acct)) {
log_message(LOG_WARN, "Login attempt on banned account: %s", username);
const char *msg = "Account banned. Contact support.\n";
write(client_output_fd, msg, strlen(msg));
return LOGIN_FAIL_ACCOUNT_BANNED;
}

// 4) Check if account is expired
if (account_is_expired(&acct)) {
log_message(LOG_WARN, "Login attempt on expired account: %s", username);
const char *msg = "Account expired. Please renew subscription.\n";
write(client_output_fd, msg, strlen(msg));
return LOGIN_FAIL_ACCOUNT_EXPIRED;
}

// 5) Enforce consecutive failure threshold (>10)
if (acct.login_fail_count > 10) {
log_message(LOG_WARN, "Account '%s' locked due to too many failures", username);
const char *msg = "Too many failed attempts. Try again later.\n";
write(client_output_fd, msg, strlen(msg));
return LOGIN_FAIL_IP_BANNED;
}

// 6) Validate provided password
if (!account_validate_password(&acct, password)) {
account_record_login_failure(&acct);
log_message(LOG_INFO, "Password mismatch for user: %s", username);
const char *msg = "Invalid username or password\n";
write(client_output_fd, msg, strlen(msg));
return LOGIN_FAIL_BAD_PASSWORD;
}

// 7) Record successful login
account_record_login_success(&acct, client_ip);

// 8) Populate session data
session->account_id      = acct.account_id;
session->session_start   = login_time;
session->expiration_time = login_time + SESSION_DURATION;

// 9) Notify client and log success
log_message(LOG_INFO, "User '%s' logged in successfully", username);
const char *msg = "Login successful\n";
write(client_output_fd, msg, strlen(msg));

return LOGIN_SUCCESS;
}

