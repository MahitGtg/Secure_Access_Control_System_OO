#include "account.h"
#include "logging.h"
#include <string.h>
#include <ctype.h>
#include <pthread.h>
// Forward declaration of panic function
void panic(const char *msg);

static pthread_mutex_t account_mutex = PTHREAD_MUTEX_INITIALIZER;
// The status check functions don't modify state, so they don't need mutex protection. 
// However, they should read consistent state.

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
                          const char *email, const char *birthdate
                      )
{
  // remove the contents of this function and replace it with your own code.
  (void) userid;
  (void) plaintext_password;
  (void) email;
  (void) birthdate;

  return NULL;
}


void account_free(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}

bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) plaintext_password;
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_plaintext_password;
  return false;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
// remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)ip;
  }

void account_record_login_failure(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void)acc;
}

bool account_is_banned(const account_t *acc) {
  if (acc == NULL) {
      log_message(LOG_ERROR, "Null pointer passed to account_is_banned");
      panic("Null pointer in account_is_banned"); // critical error - abort
      return true; // Fail secure
  }

  // thread safe - acquire lock for reading
  pthread_mutex_lock(&account_mutex);

  // getting unban time
  time_t unban_time = acc->unban_time;

  // thread safe - release lock
  pthread_mutex_unlock(&account_mutex);

  // special case: 0 means not banned
  if (acc->unban_time == 0) {
      return false;
  }  

 // getting current time
  time_t current_time = time(NULL);
  if (current_time == (time_t)-1) {
      log_message(LOG_ERROR, "Failed to get current time in account_is_banned");
      return true; // fail secure
  }
  // checking if ban time is in the future
  return (acc->unban_time > current_time);
}

bool account_is_expired(const account_t *acc) {
if (acc == NULL) {
    log_message(LOG_ERROR, "Null pointer passed to account_is_expired");
    panic("Null pointer in account_is_expired"); // critical error - abort
    return true; // Fail secure - assume expired if we can't verify
}

// thread safe - acquire lock for reading
pthread_mutex_lock(&account_mutex);

// getting expiration time
time_t expiration_time = acc->expiration_time;

// thread safe - release lock
pthread_mutex_unlock(&account_mutex);

// special case: 0 means no expiration
if (acc->expiration_time == 0) {
    return false;
}

// getting current time
time_t current_time = time(NULL);
if (current_time == (time_t)-1) {
    log_message(LOG_ERROR, "Failed to get current time in account_is_expired");
    return true; // Fail secure
}

// checking if expiration time is in the past
return (acc->expiration_time <= current_time);
}

void account_set_unban_time(account_t *acc, time_t t) {
  // checking for NULL pointers
  if (acc == NULL) {
      log_message(LOG_ERROR, "Null pointer passed to account_set_unban_time");
      panic("Null pointer in account_set_unban_time"); // critical error - abort
      return;
  }

  // checking if unban time is in the past
  time_t current_time = time(NULL);
  if (current_time != (time_t)-1 && t != 0 && t < current_time) {
      log_message(LOG_WARN, "Setting unban time to a value in the past: %ld", (long)t);
  }
  
  // thread safe - acquire lock
  pthread_mutex_lock(&account_mutex);

  // setting the unban time
  acc->unban_time = t;

  // thread safe - release lock
  pthread_mutex_unlock(&account_mutex);

  // logging the update
  log_message(LOG_INFO, "Unban time set for user %s", acc->userid);
}

void account_set_expiration_time(account_t *acc, time_t t) {
  if (acc == NULL) {
      log_message(LOG_ERROR, "Null pointer passed to account_set_expiration_time");
      panic("Null pointer in account_set_expiration_time"); // critical error - abort
      return;
  }

  // checking if expiration time is in the past    
  time_t current_time = time(NULL);
  if (current_time != (time_t)-1 && t != 0 && t < current_time) {
      log_message(LOG_WARN, "Setting expiration time to a value in the past: %ld", (long)t);
  }

  // thread safe - acquire lock
  pthread_mutex_lock(&account_mutex);

  // setting the expiration time
  acc->expiration_time = t;
  
  // thread safe - release lock
  pthread_mutex_unlock(&account_mutex);

  // logging the update
  log_message(LOG_INFO, "Expiration time set for user %s", acc->userid);
}

void account_set_email(account_t *acc, const char *new_email) {
  // checking for NULL pointers
  if (acc == NULL || new_email == NULL) {
      log_message(LOG_ERROR, "Null pointer passed to account_set_email");
      panic("Null pointer in account_set_email"); // critical error - abort
      return;
  }

  // using strnlen for length check --> safe practice
  size_t email_len = strnlen(new_email, EMAIL_LENGTH);

  // checking if email is too long
  if (email_len >= EMAIL_LENGTH) {
      log_message(LOG_ERROR, "Email too long (max %d chars)", EMAIL_LENGTH - 1);
      return;
  }

  // checking if email is in valid format - ASCII printable characters only, no spaces
  for (size_t i = 0; i < email_len; i++) {
      if (!isprint(new_email[i]) || isspace(new_email[i])) {
          log_message(LOG_ERROR, "Invalid character in emailat position %zu", i);
          return;
      }
  }

  // thread safe - acquire lock
  pthread_mutex_lock(&account_mutex);

  // copying email to account struct
  strncpy(acc->email, new_email, EMAIL_LENGTH - 1);
  // ensuring null termination
  acc->email[EMAIL_LENGTH - 1] = '\0';

  // thread safe - release lock
  pthread_mutex_unlock(&account_mutex);

  // logging the update
  log_message(LOG_INFO, "Email updated for user %s", acc->userid);
}

bool account_print_summary(const account_t *acct, int fd) {
  // remove the contents of this function and replace it with your own code.
  (void)acct;
  (void)fd;
  return false;
}