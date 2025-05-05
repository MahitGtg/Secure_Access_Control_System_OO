#include "account.h"
#include <string.h>
#include <sodium.h>
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h> /* For isdigit() */

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

bool account_validate_password(const account_t *acc, const char *plaintext_password) {
    /* Parameter validation */
    if (!acc) {
        log_message(LOG_ERROR, "account_validate_password: account pointer is NULL");
        return false;
    }
    
    if (!plaintext_password) {
        log_message(LOG_ERROR, "account_validate_password: password pointer is NULL");
        return false;
    }
    
    /* Check if password hash is empty */
    if (acc->password_hash[0] == '\0') {
        log_message(LOG_ERROR, "account_validate_password: account has no password hash");
        return false;
    }
    
    /* Check if password is in argon2id format */
    if (strncmp(acc->password_hash, "$argon2id$", 10) != 0) {
        log_message(LOG_ERROR, "account_validate_password: password hash is not in argon2id format");
        return false;
    }
    
    /* Input validation - prevent DoS with excessively long passwords */
    size_t password_len = strlen(plaintext_password);
    if (password_len > 1024) {
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
    if (result != 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 50000000; /* 50ms delay */
        nanosleep(&ts, NULL);
    }
    
    return result == 0;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
    /* Parameter validation */
    if (!acc) {
        log_message(LOG_ERROR, "account_update_password: account pointer is NULL");
        return false;
    }
    
    if (!new_plaintext_password) {
        log_message(LOG_ERROR, "account_update_password: password pointer is NULL");
        return false;
    }
    
    /* Check password length - empty passwords are not allowed */
    size_t password_len = strlen(new_plaintext_password);
    if (password_len == 0) {
        log_message(LOG_ERROR, "account_update_password: empty password not allowed");
        return false;
    }
    
    /* Check password length - too long passwords are not allowed (prevent DoS) */
    if (password_len > 1024) {
        log_message(LOG_ERROR, "account_update_password: password too long (max 1024 chars)");
        return false;
    }
    
    /* Password complexity requirements */
    bool has_uppercase = false;
    bool has_lowercase = false;
    bool has_digit = false;
    bool has_special = false;
    
    for (size_t i = 0; i < password_len; i++) {
        char c = new_plaintext_password[i];
        if (isupper((unsigned char)c)) has_uppercase = true;
        else if (islower((unsigned char)c)) has_lowercase = true;
        else if (isdigit((unsigned char)c)) has_digit = true;
        else has_special = true;
    }
    
    /* Minimum length requirement */
    if (password_len < 8) {
        log_message(LOG_ERROR, "account_update_password: password too short (min 8 chars)");
        return false;
    }
    
    /* Complexity requirement: must have at least 3 character classes */
    int complexity_score = (has_uppercase ? 1 : 0) + 
                          (has_lowercase ? 1 : 0) + 
                          (has_digit ? 1 : 0) + 
                          (has_special ? 1 : 0);
                          
    if (complexity_score < 3) {
        log_message(LOG_ERROR, "account_update_password: password not complex enough");
        log_message(LOG_ERROR, "Password must contain at least 3 of: uppercase, lowercase, digits, special chars");
        return false;
    }
    
    /* Initialize libsodium if not already initialized */
    if (sodium_init() < 0) {
        log_message(LOG_ERROR, "account_update_password: failed to initialize libsodium");
        return false;
    }
    
    /* Generate the password hash with Argon2id */
    char hashed_password[HASH_LENGTH] = {0};
    
    /* Ensure we have enough space for the hash */
    if (HASH_LENGTH < crypto_pwhash_STRBYTES) {
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
            mem_limit) != 0) {
        
        log_message(LOG_ERROR, "account_update_password: password hashing failed");
        return false;
    }
    
    /* Ensure hash string is null-terminated and within length limits */
    size_t hash_len = strlen(hashed_password);
    if (hash_len >= HASH_LENGTH) {
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
void account_record_login_success(account_t *acc, ip4_addr_t ip)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
  (void)ip;
}

void account_record_login_failure(account_t *acc)
{
  // remove the contents of this function and replace it with your own code.
  (void)acc;
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
  // remove the contents of this function and replace it with your own code.
  (void)acct;
  (void)fd;
  return false;
}
