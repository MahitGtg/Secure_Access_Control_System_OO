#include "account.h"
#include <string.h>
#include <sodium.h>
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h> /* For isdigit() */
#include "banned.h"
#include "logging.h"
#include <string.h>
#include <ctype.h>
#include <pthread.h>

// Forward declaration of panic function
void panic(const char *msg);

// Forward declaration of panic function - CAN WE DO THAT?  otherwise check doesnt work in test
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
/**
 * Validates if a supplied plaintext password matches the stored hash.
 *
 * This function securely compares the given plaintext password against
 * the password hash stored in the account structure using the Argon2id
 * algorithm. It implements constant-time verification to prevent timing attacks.
 *
 * @param acc Pointer to the account structure containing the password hash
 * @param plaintext_password The plaintext password to verify
 *
 * @pre acc must not be NULL
 * @pre plaintext_password must not be NULL
 * @pre acc->password_hash must contain a valid Argon2id hash
 *
 * @return true if the password matches, false otherwise
 */
bool account_validate_password(const account_t *acc, const char *plaintext_password)
{
  /* Parameter validation */
  if (!acc)
  {
    log_message(LOG_ERROR, "account_validate_password: account pointer is NULL");
    return false;
  }

  if (!plaintext_password)
  {
    log_message(LOG_ERROR, "account_validate_password: password pointer is NULL");
    return false;
  }

  /* Check if password hash is empty */
  if (acc->password_hash[0] == '\0')
  {
    log_message(LOG_ERROR, "account_validate_password: account has no password hash");
    return false;
  }

  /* Check if password is in argon2id format */
  if (strncmp(acc->password_hash, "$argon2id$", 10) != 0)
  {
    log_message(LOG_ERROR, "account_validate_password: password hash is not in argon2id format");
    return false;
  }

  /* Input validation - prevent DoS with excessively long passwords */
  size_t password_len = strlen(plaintext_password);
  if (password_len > 1024)
  {
    log_message(LOG_ERROR, "account_validate_password: password too long (max 1024 chars)");
    return false;
  }

  /* Use libsodium to validate the password with constant-time verification */
  int result = crypto_pwhash_str_verify(
      acc->password_hash,
      plaintext_password,
      password_len);

  /*
   * Following POLP: Add constant-time delay on failure to prevent timing attacks
   * This makes it harder to determine if a username exists based on response time
   */
  #ifndef TESTING
  if (result != 0)
  {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 50000000; /* 50ms delay */
    nanosleep(&ts, NULL);
  }
  #endif

  return result == 0;
}

/**
 * Updates an account's password with a new securely hashed password.
 *
 * This function validates the new password for complexity requirements,
 * then generates a new Argon2id hash with a cryptographically secure
 * random salt. The hash is stored in the account structure. Old password
 * data is securely wiped from memory.
 *
 * Password complexity requirements:
 * - Minimum 8 characters
 * - Maximum 1024 characters
 * - Must contain at least 3 of: uppercase, lowercase, digits, special characters
 *
 * @param acc Pointer to the account structure to update
 * @param new_plaintext_password The new plaintext password
 *
 * @pre acc must not be NULL
 * @pre new_plaintext_password must not be NULL
 *
 * @return true if the password was successfully updated, false otherwise
 */
bool account_update_password(account_t *acc, const char *new_plaintext_password)
{
  /* Parameter validation */
  if (!acc)
  {
    log_message(LOG_ERROR, "account_update_password: account pointer is NULL");
    return false;
  }

  if (!new_plaintext_password)
  {
    log_message(LOG_ERROR, "account_update_password: password pointer is NULL");
    return false;
  }

  /* Check password length - empty passwords are not allowed */
  size_t password_len = strlen(new_plaintext_password);
  if (password_len == 0)
  {
    log_message(LOG_ERROR, "account_update_password: empty password not allowed");
    return false;
  }

  /* Check password length - too long passwords are not allowed (prevent DoS) */
  if (password_len > 1024)
  {
    log_message(LOG_ERROR, "account_update_password: password too long (max 1024 chars)");
    return false;
  }

  /* Password complexity requirements */
  bool has_uppercase = false;
  bool has_lowercase = false;
  bool has_digit = false;
  bool has_special = false;

  for (size_t i = 0; i < password_len; i++)
  {
    char c = new_plaintext_password[i];
    if (isupper((unsigned char)c))
      has_uppercase = true;
    else if (islower((unsigned char)c))
      has_lowercase = true;
    else if (isdigit((unsigned char)c))
      has_digit = true;
    else
      has_special = true;
  }

  /* Minimum length requirement */
  if (password_len < 8)
  {
    log_message(LOG_ERROR, "account_update_password: password too short (min 8 chars)");
    return false;
  }

  /* Complexity requirement: must have at least 3 character classes */
  int complexity_score = (has_uppercase ? 1 : 0) +
                         (has_lowercase ? 1 : 0) +
                         (has_digit ? 1 : 0) +
                         (has_special ? 1 : 0);

  if (complexity_score < 3)
  {
    log_message(LOG_ERROR, "account_update_password: password not complex enough");
    log_message(LOG_ERROR, "Password must contain at least 3 of: uppercase, lowercase, digits, special chars");
    return false;
  }

  /* Initialize libsodium if not already initialized */
  if (sodium_init() < 0)
  {
    log_message(LOG_ERROR, "account_update_password: failed to initialize libsodium");
    return false;
  }

  /* Generate the password hash with Argon2id */
  char hashed_password[HASH_LENGTH] = {0};

  /* Ensure we have enough space for the hash */
  if (HASH_LENGTH < crypto_pwhash_STRBYTES)
  {
    log_message(LOG_ERROR, "account_update_password: HASH_LENGTH too small for libsodium hash");
    return false;
  }

  /*
   * Use more secure parameters than the defaults
   * Increase computation time to make brute-force attacks harder
   */
  unsigned long long ops_limit = crypto_pwhash_OPSLIMIT_INTERACTIVE * 2;
  size_t mem_limit = crypto_pwhash_MEMLIMIT_INTERACTIVE;

  if (crypto_pwhash_str(
          hashed_password,
          new_plaintext_password,
          password_len,
          ops_limit,
          mem_limit) != 0)
  {

    log_message(LOG_ERROR, "account_update_password: password hashing failed");
    return false;
  }

  /* Ensure hash string is null-terminated and within length limits */
  size_t hash_len = strlen(hashed_password);
  if (hash_len >= HASH_LENGTH)
  {
    log_message(LOG_ERROR, "account_update_password: generated hash too long");
    /* Securely wipe the hash buffer */
    sodium_memzero(hashed_password, HASH_LENGTH);
    return false;
  }

 /* Securely wipe the old password hash following POLP */
  sodium_memzero(acc->password_hash, HASH_LENGTH);

  /* Copy the new hash to the account with length check to prevent buffer overflow */
  strncpy(acc->password_hash, hashed_password, HASH_LENGTH - 1);
  acc->password_hash[HASH_LENGTH - 1] = '\0'; /* Ensure null-termination */

  /* Securely wipe the temporary hash buffer to prevent memory scraping */
  sodium_memzero(hashed_password, HASH_LENGTH);

  log_message(LOG_INFO, "account_update_password: password updated successfully");
  return true;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
  if (acc == NULL) {
      log_message(LOG_ERROR, "Null pointer passed to account_record_login_success");
      panic("Null pointer in account_record_login_success");
      return;
  }
  
  // getting current time
  time_t current_time = time(NULL);
  if (current_time == (time_t)-1) {
      log_message(LOG_ERROR, "Failed to get current time in account_record_login_success");
      return;
  }
  
  // thread safe - acquire lock
  pthread_mutex_lock(&account_mutex);
  
  // updating account fields
  acc->login_count++;
  acc->login_fail_count = 0; // reset consecutive failure count on success
  acc->last_login_time = current_time;
  acc->last_ip = ip;
  
  // thread safe - release lock
  pthread_mutex_unlock(&account_mutex);
  
  log_message(LOG_INFO, "Recorded successful login for user %s", acc->userid);
}

void account_record_login_failure(account_t *acc) {
  if (acc == NULL) {
      log_message(LOG_ERROR, "Null pointer passed to account_record_login_failure");
      panic("Null pointer in account_record_login_failure");
      return;
  }
  
  // thread safe - acquire lock
  pthread_mutex_lock(&account_mutex);
  
  // updating account fields
  acc->login_count = 0; // reset success count on failure
  acc->login_fail_count++;
  
  // thread safe - release lock
  pthread_mutex_unlock(&account_mutex);
  
  log_message(LOG_INFO, "Recorded login failure for user %s (consecutive failures: %u)", 
              acc->userid, acc->login_fail_count);
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
  if (unban_time == 0) {
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
time_t current_time = time(NULL);
if (current_time == (time_t)-1) {
    log_message(LOG_ERROR, "Failed to get current time in account_is_expired");
    pthread_mutex_unlock(&account_mutex);
    return true; // Fail secure
}

// special case: 0 means no expiration
if (acc->expiration_time == 0) {
    pthread_mutex_unlock(&account_mutex);
    return false;
}

// checking if expiration time is in the past
bool is_expired = (acc->expiration_time <= current_time);

// thread safe - release lock
pthread_mutex_unlock(&account_mutex);

return is_expired;
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
  if (acct == NULL) {
      log_message(LOG_ERROR, "Null pointer passed to account_print_summary");
      panic("Null pointer in account_print_summary");
      return false;
  }
  
  // buffer for formatting time
  char time_buffer[64];
  struct tm tm_info;
  
  // format for printing
  const char *summary_format = 
      "Account Summary for: %s\n"
      "Email: %s\n"
      "Login Count: %u\n"
      "Failed Login Attempts: %u\n"
      "Last Login: %s\n"
      "Last IP: %u.%u.%u.%u\n"
      "Account Status: %s\n"
      "Birth Date: %s\n";
  
  // getting account status
  bool is_banned = account_is_banned(acct);
  bool is_expired = account_is_expired(acct);
  const char *status = is_banned ? "BANNED" : 
                      (is_expired ? "EXPIRED" : "ACTIVE");
  
  // formatting last login time
  if (acct->last_login_time == 0) {
      strcpy(time_buffer, "Never");
  } else if (localtime_r(&acct->last_login_time, &tm_info) != NULL) {
      strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
  } else {
      strcpy(time_buffer, "Invalid time");
  }
  
  // extracting IP address bytes
  unsigned char ip_bytes[4];
  ip_bytes[0] = (acct->last_ip >> 24) & 0xFF;
  ip_bytes[1] = (acct->last_ip >> 16) & 0xFF;
  ip_bytes[2] = (acct->last_ip >> 8) & 0xFF;
  ip_bytes[3] = acct->last_ip & 0xFF;
  
  // writing to file descriptor
  int ret = dprintf(fd, summary_format,
                    acct->userid,
                    acct->email,
                    acct->login_count,
                    acct->login_fail_count,
                    time_buffer,
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                    status,
                    acct->birthdate);
  
  if (ret < 0) {
      log_message(LOG_ERROR, "Failed to write account summary to file descriptor");
      return false;
  }
  
  return true;
}