#define _POSIX_C_SOURCE 200809L
#include "account.h"
#include <string.h>
#include <sodium.h>
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h> /* For isdigit() */
#include <pthread.h>
#include <stdbool.h>
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

// Implementation of panic function
static void panic(const char *msg)
{
    log_message(LOG_ERROR, "PANIC: %s", msg);
    abort();
}

static pthread_mutex_t account_mutex = PTHREAD_MUTEX_INITIALIZER;
// The status check functions don't modify state, so they don't need mutex protection.
// However, they should read consistent state.

// Helper: check if email is ASCII printable and has no spaces
static bool is_valid_email(const char *email)
{
    if (!email)
        return false;
    if (!strchr(email, '@'))
    {
        log_message(LOG_ERROR, "account_create: Invalid email format (missing @)");
        return false; // Return false, not NULL
    }
    for (const char *p = email; *p; ++p)
    {
        if (*p == ' ' || !isprint((unsigned char)*p) || (unsigned char)*p > 127)
            return false;
    }
    return true;
}

// Helper: check if birthdate is YYYY-MM-DD and valid
static bool is_valid_birthdate(const char *birthdate)
{
    if (!birthdate)
        return false;
    // Must be exactly 10 chars: YYYY-MM-DD
    if (strlen(birthdate) != 10)
        return false;
    // Check format
    for (int i = 0; i < 10; ++i)
    {
        if (i == 4 || i == 7)
        {
            if (birthdate[i] != '-')
                return false;
        }
        else
        {
            if (!isdigit((unsigned char)birthdate[i]))
                return false;
        }
    }
    // Check valid month/day
    char *endptr;
    int year = (int)strtol(birthdate, &endptr, 10);
    int month = (int)strtol(birthdate + 5, &endptr, 10);
    int day = (int)strtol(birthdate + 8, &endptr, 10);
    if (month < 1 || month > 12)
        return false;
    if (day < 1 || day > 31)
        return false;
    // Basic day check for each month
    static const int days_in_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int max_day = days_in_month[month - 1];
    // Leap year for February
    if (month == 2 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)))
        max_day = 29;
    if (day > max_day)
        return false;
    return true;
}

/**
 * Creates a new account with the specified parameters.
 *
 * This function initializes a new account structure with:
 * - User ID
 * - Securely hashed password
 * - Email address
 * - Birthdate
 *
 * The function performs validation on all inputs and securely
 * handles the password using libsodium's Argon2id implementation.
 *
 * @param userid The user ID for the account
 * @param plaintext_password The password to hash and store
 * @param email The email address for the account
 * @param birthdate The birthdate in YYYY-MM-DD format
 * @return Pointer to the new account structure, or NULL on failure
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate)
{
    if (!userid || !plaintext_password || !email || !birthdate)
    {
        log_message(LOG_ERROR, "account_create: NULL argument provided");
        return NULL;
    }
    if (!*userid || !*plaintext_password || !*email || !*birthdate)
    {
        log_message(LOG_ERROR, "account_create: Empty string argument provided");
        return NULL;
    }
    if (!is_valid_email(email))
    {
        log_message(LOG_ERROR, "account_create: Invalid email format");
        return NULL;
    }
    if (!is_valid_birthdate(birthdate))
    {
        log_message(LOG_ERROR, "account_create: Invalid birthdate format");
        return NULL;
    }

    account_t *acc = (account_t *)malloc(sizeof(account_t));
    if (!acc)
    {
        log_message(LOG_ERROR, "account_create: Memory allocation failed");
        return NULL;
    }
    memset(acc, 0, sizeof(account_t));

    // Copy user data with proper null termination
    strncpy(acc->userid, userid, USER_ID_LENGTH - 1);
    acc->userid[USER_ID_LENGTH - 1] = '\0';
    strncpy(acc->email, email, EMAIL_LENGTH - 1);
    acc->email[EMAIL_LENGTH - 1] = '\0';
    // Use memcpy for birthdate: fixed length, not null-terminated
    memcpy(acc->birthdate, birthdate, BIRTHDATE_LENGTH); // Safe: exactly 10 bytes, no null terminator

    if (sodium_init() < 0)
    {
        log_message(LOG_ERROR, "account_create: libsodium initialization failed");
        free(acc);
        return NULL;
    }
    if (crypto_pwhash_str(acc->password_hash, plaintext_password, strlen(plaintext_password),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0)
    {
        log_message(LOG_ERROR, "account_create: password hashing failed");
        free(acc);
        return NULL;
    }
    return acc;
}

/**
 * Frees an account structure and securely wipes its contents.
 *
 * This function:
 * - Securely wipes the account memory using sodium_memzero
 * - Frees the allocated memory
 * - Safely handles NULL pointers
 *
 * @param acc Pointer to the account structure to free
 */
void account_free(account_t *acc)
{
    if (!acc)
        return;
    sodium_memzero(acc, sizeof(account_t));
    free(acc);
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

/**
 * Records a successful login attempt for an account.
 *
 * This function updates the account's:
 * - Login count
 * - Last login time
 * - Last IP address
 *
 * @param acc Pointer to the account structure
 * @param ip The IPv4 address of the successful login
 */
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
    const struct tm *tm_info = localtime(&acc->last_login_time);
    if (tm_info) {
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    }

    log_message(LOG_INFO,
        "[account_record_login_success]: User '%s' logged in from IP '%s' at '%s'.",
        acc->userid, ip_str, time_str);

  pthread_mutex_unlock(&acc_mutex);
}


/**
 * Records a failed login attempt for an account.
 *
 * This function updates the account's:
 * - Failed login count
 * - May trigger account banning based on failed attempts
 *
 * @param acc Pointer to the account structure
 */
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

/**
 * Checks if an account is currently banned.
 *
 * This function:
 * - Is thread-safe using mutex protection
 * - Implements fail-secure behavior
 * - Returns true if the account is banned, false otherwise
 *
 * @param acc Pointer to the account structure to check
 * @return true if the account is banned, false otherwise
 */
bool account_is_banned(const account_t *acc)
{
    if (acc == NULL)
    {
        log_message(LOG_ERROR, "Null pointer passed to account_is_banned");
        panic("Null pointer in account_is_banned"); // critical error - abort
        return true;                                // Fail secure
    }

    // thread safe - acquire lock for reading
    pthread_mutex_lock(&account_mutex);

    // getting unban time
    time_t unban_time = acc->unban_time;

    // thread safe - release lock
    pthread_mutex_unlock(&account_mutex);

    // special case: 0 means not banned
    if (unban_time == 0)
    {
        return false;
    }

    // getting current time
    time_t current_time = time(NULL);
    if (current_time == (time_t)-1)
    {
        log_message(LOG_ERROR, "Failed to get current time in account_is_banned");
        return true; // fail secure
    }
    // checking if ban time is in the future
    return (unban_time > current_time);
}

/**
 * Checks if an account has expired.
 *
 * This function:
 * - Is thread-safe using mutex protection
 * - Implements fail-secure behavior
 * - Returns true if the account is expired, false otherwise
 *
 * @param acc Pointer to the account structure to check
 * @return true if the account is expired, false otherwise
 */
bool account_is_expired(const account_t *acc)
{
    if (acc == NULL)
    {
        log_message(LOG_ERROR, "Null pointer passed to account_is_expired");
        panic("Null pointer in account_is_expired"); // critical error - abort
        return true;                                 // Fail secure - assume expired if we can't verify
    }

    // thread safe - acquire lock for reading
    pthread_mutex_lock(&account_mutex);

    // getting expiration time
    time_t expiration_time = acc->expiration_time;

    // thread safe - release lock
    pthread_mutex_unlock(&account_mutex);

    // special case: 0 means no expiration
    if (expiration_time == 0)
    {
        return false;
    }

    // getting current time
    time_t current_time = time(NULL);
    if (current_time == (time_t)-1)
    {
        log_message(LOG_ERROR, "Failed to get current time in account_is_expired");
        return true; // Fail secure
    }

    // checking if expiration time is in the past
    return (expiration_time <= current_time);
}

/**
 * Sets the unban time for an account.
 *
 * This function:
 * - Is thread-safe using mutex protection
 * - Updates the account's unban time
 * - Logs the update
 *
 * @param acc Pointer to the account structure
 * @param t The new unban time (Unix timestamp)
 */
void account_set_unban_time(account_t *acc, time_t t)
{
    if (acc == NULL)
    {
        log_message(LOG_ERROR, "Null pointer passed to account_set_unban_time");
        panic("Null pointer in account_set_unban_time"); // critical error - abort
        return;
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

/**
 * Sets the expiration time for an account.
 *
 * This function:
 * - Is thread-safe using mutex protection
 * - Validates the expiration time is not in the past
 * - Updates the account's expiration time
 * - Logs the update
 *
 * @param acc Pointer to the account structure
 * @param t The new expiration time (Unix timestamp)
 */
void account_set_expiration_time(account_t *acc, time_t t)
{
    if (acc == NULL)
    {
        log_message(LOG_ERROR, "Null pointer passed to account_set_expiration_time");
        panic("Null pointer in account_set_expiration_time"); // critical error - abort
        return;
    }

    // checking if expiration time is in the past
    time_t current_time = time(NULL);
    if (current_time != (time_t)-1 && t != 0 && t < current_time)
    {
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

/**
 * Updates an account's email address.
 *
 * This function:
 * - Is thread-safe using mutex protection
 * - Validates the email format
 * - Ensures the email is not too long
 * - Updates the account's email
 * - Logs the update
 *
 * @param acc Pointer to the account structure
 * @param new_email The new email address to set
 */
void account_set_email(account_t *acc, const char *new_email)
{
    // checking for NULL pointers
    if (acc == NULL || new_email == NULL)
    {
        log_message(LOG_ERROR, "Null pointer passed to account_set_email");
        panic("Null pointer in account_set_email"); // critical error - abort
        return;
    }

    // using strlen for length check since we're checking length anyway
    size_t email_len = strlen(new_email);

    // checking if email is too long
    if (email_len >= EMAIL_LENGTH)
    {
        log_message(LOG_ERROR, "Email too long (max %d chars)", EMAIL_LENGTH - 1);
        return;
    }

    // checking if email is in valid format - ASCII printable characters only, no spaces
    for (size_t i = 0; i < email_len; i++)
    {
        if (!isprint((unsigned char)new_email[i]) || isspace((unsigned char)new_email[i]))
        {
            log_message(LOG_ERROR, "Invalid character in email at position %zu", i);
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


/**
 * Prints a summary of an account to a file descriptor.
 *
 * This function: 
 * - Prints account information in a human-readable format
 * - Includes user ID, email, and status information
 * - Uses the provided file descriptor for output
 *
 * @param acct Pointer to the account structure to print
 * @param fd File descriptor to write the summary to
 * @return true on success, false on failure
 */
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
        const struct tm *lt = localtime(&acct->last_login_time);
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



