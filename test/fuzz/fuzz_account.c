// test/fuzz/fuzz_account.c
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "account.h"
#include "logging.h"

// Stub to suppress logging during fuzzing
void log_message(log_level_t level, const char *fmt, ...) {
    // Do nothing
    (void)level;
    (void)fmt;
}

// Main fuzzing entry point for account functions
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Need at least some data to be useful
    if (size < 4) 
        return 0;
    
    // Create null-terminated strings from fuzzer data
    char *userid = (char *)malloc(size + 1);
    char *password = (char *)malloc(size + 1);
    char *email = (char *)malloc(size + 1);
    char *birthdate = (char *)malloc(11); // Fixed size for birthdate
    
    if (!userid || !password || !email || !birthdate) {
        free(userid);
        free(password);
        free(email);
        free(birthdate);
        return 0;
    }
    
    // Split the input data into parts for different parameters
    size_t part_size = size / 4;
    
    // Copy and null-terminate userid
    memcpy(userid, data, part_size);
    userid[part_size] = '\0';
    
    // Copy and null-terminate password
    memcpy(password, data + part_size, part_size);
    password[part_size] = '\0';
    
    // Copy and null-terminate email
    memcpy(email, data + 2 * part_size, part_size);
    email[part_size] = '\0';
    
    // Create a valid-looking birthdate (YYYY-MM-DD) from the last part of data
    snprintf(birthdate, 11, "20%02x-%02x-%02x", 
             data[3 * part_size] % 100,
             (data[3 * part_size + 1] % 12) + 1, 
             (data[3 * part_size + 2] % 28) + 1);
    
    // Test account_create
    account_t *acc = account_create(userid, password, email, birthdate);
    
    if (acc) {
        // If account creation succeeded, test other functions
        account_validate_password(acc, password);
        account_update_password(acc, password);
        account_is_banned(acc);
        account_is_expired(acc);
        account_set_unban_time(acc, 0);
        account_set_expiration_time(acc, 0);
        account_set_email(acc, email);
        
        // Create a temporary file for print_summary testing
        FILE *temp = tmpfile();
        if (temp) {
            account_print_summary(acc, fileno(temp));
            fclose(temp);
        }
        
        account_free(acc);
    }
    
    free(userid);
    free(password);
    free(email);
    free(birthdate);
    
    return 0;
}