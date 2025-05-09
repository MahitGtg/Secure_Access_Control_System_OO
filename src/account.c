#include "account.h"
#include <string.h>
#include <sodium.h>
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h> /* For isdigit() */
#include <unistd.h>
#include <limits.h>    // for UINT_MAX
#include <pthread.h>
#include <stdint.h>  // for uint8_t
#include <arpa/inet.h>


static pthread_mutex_t acc_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool safe_fd_printf(int fd, const char *fmt, ...) {
  char buffer[512];
  va_list args;
  va_start(args, fmt);
  int len = vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);

  if (len < 0 || (size_t)len >= sizeof(buffer)) {
      return false;
  }

  return write(fd, buffer, (size_t)len) == (ssize_t)len;
}

/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate)
{
  // remove the contents of this function and replace it with your own code.
  (void)userid;
  (void)plaintext_password;
  (void)email;
  (void)birthdate;

  return NULL;
}

void account_free(account_t *acc)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
}

bool account_validate_password(const account_t *acc, const char *plaintext_password)
{
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) plaintext_password;
  return false;
}


bool account_update_password(account_t *acc, const char *new_plaintext_password)
{
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_plaintext_password;
  return false;
}


void account_record_login_success(account_t *acc, ip4_addr_t ip)
{
  if (!acc) {
    log_message(LOG_ERROR, "account_record_login_success: NULL account pointer");
    return;
  }

  pthread_mutex_lock(&acc_mutex);

  acc->login_count++;
  acc->login_fail_count = 0;
  acc->last_login_time = time(NULL);
  acc->last_ip = ip;

  struct in_addr addr = { .s_addr = ip };
    char ip_str[INET_ADDRSTRLEN] = "unknown";
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    // Inline time formatting
    char time_str[64] = "invalid";
    struct tm *tm_info = localtime(&acc->last_login_time);
    if (tm_info) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    }

    log_message(LOG_INFO,
        "[account_record_login_success]: User '%s' logged in from IP '%s' at '%s'.",
        acc->userid, ip_str, time_str);

  pthread_mutex_unlock(&acc_mutex);
}

void account_record_login_failure(account_t *acc)
{
  if (!acc) {
    log_message(LOG_ERROR, "account_record_login_failure: NULL account pointer");
    return;
  }

  pthread_mutex_lock(&acc_mutex);

  if (acc->login_fail_count < UINT_MAX) {
    acc->login_fail_count++;
}
acc->login_count = 0;

log_message(LOG_INFO,
    "[account_record_login_failure]: Failure #%u for user '%s'.",
    acc->login_fail_count, acc->userid);

  pthread_mutex_unlock(&acc_mutex);
}

bool account_is_banned(const account_t *acc)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  return false;
}

bool account_is_expired(const account_t *acc)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  return false;
}

void account_set_unban_time(account_t *acc, time_t t)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)t;
}

void account_set_expiration_time(account_t *acc, time_t t)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)t;
}

void account_set_email(account_t *acc, const char *new_email)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)new_email;
}



bool account_print_summary(const account_t *acct, int fd)
{
    if (!acct || fd < 0) {
        log_message(LOG_ERROR, "account_print_summary: Invalid arguments");
        return false;
    }

    safe_fd_printf(fd, "=== Account Summary ===\n");
    safe_fd_printf(fd, "User ID: %s\n", acct->userid);
    safe_fd_printf(fd, "Email: %s\n", acct->email);
    safe_fd_printf(fd, "Birthdate: %s\n", acct->birthdate);
    safe_fd_printf(fd, "Login Count: %u\n", acct->login_count);
    safe_fd_printf(fd, "Login Failures: %u\n", acct->login_fail_count);

    
    char time_str[64] = "N/A";
    if (acct->last_login_time > 0) {
        struct tm *lt = localtime(&acct->last_login_time);
        if (lt) {
            strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", lt);
        }
    }

    
    struct in_addr addr = { .s_addr = acct->last_ip };
    char ip_str[INET_ADDRSTRLEN] = "unavailable";
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    safe_fd_printf(fd, "Last Login IP: %s\n", ip_str);
    safe_fd_printf(fd, "Last Login Time: %s\n", time_str);
    safe_fd_printf(fd, "=======================\n");

    log_message(LOG_INFO,
        "[account_print_summary]: Printed summary for user '%s'.", acct->userid);

    return true;
}