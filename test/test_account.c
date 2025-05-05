#include <check.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>
#include "../src/account.h"

// Helper to create a dummy account with a known password
void setup_account(account_t *acc, const char *password)
{
    memset(acc, 0, sizeof(account_t));
    strncpy(acc->userid, "testuser", USER_ID_LENGTH - 1);
    strncpy(acc->email, "test@example.com", EMAIL_LENGTH - 1);
    
    // Fix the truncation warning
    strncpy(acc->birthdate, "2000-01-01", BIRTHDATE_LENGTH - 1);
    acc->birthdate[BIRTHDATE_LENGTH - 1] = '\0';  // Ensure null-termination
    
    if (!account_update_password(acc, password)) {
        fprintf(stderr, "Failed to set initial password\n");
    }
}

// Test case for password validation
START_TEST(test_validate_password)
{
    account_t acc;
    setup_account(&acc, "TestPass123!");
    
    // Correct password
    ck_assert(account_validate_password(&acc, "TestPass123!"));
    
    // Wrong password
    ck_assert(!account_validate_password(&acc, "WrongPass"));
    
    // Empty password
    ck_assert(!account_validate_password(&acc, ""));
    
    // Too long password
    char longpw[1100];
    memset(longpw, 'a', 1099);
    longpw[1099] = '\0';
    ck_assert(!account_validate_password(&acc, longpw));
}
END_TEST

// Test case for password updates
START_TEST(test_update_password)
{
    account_t acc;
    setup_account(&acc, "Start123!");
    
    // Update to a new valid password
    ck_assert(account_update_password(&acc, "NewPass456!"));
    ck_assert(account_validate_password(&acc, "NewPass456!"));
    ck_assert(!account_validate_password(&acc, "Start123!"));
    
    // Too short
    ck_assert(!account_update_password(&acc, "aB1!"));
    
    // Not complex enough
    ck_assert(!account_update_password(&acc, "alllowercase"));
    ck_assert(!account_update_password(&acc, "ALLUPPERCASE"));
    ck_assert(!account_update_password(&acc, "12345678"));
    
    // Too long
    char longpw[1100];
    memset(longpw, 'a', 1099);
    longpw[1099] = '\0';
    ck_assert(!account_update_password(&acc, longpw));
}
END_TEST

// Setup the test suite
Suite *password_suite(void)
{
    Suite *s = suite_create("Password");
    TCase *tc_core = tcase_create("Core");
    
    // Add a timeout setting to prevent test timeouts
    tcase_set_timeout(tc_core, 60); // Set timeout to 60 seconds
    
    // Add test cases to the test case
    tcase_add_test(tc_core, test_validate_password);
    tcase_add_test(tc_core, test_update_password);
    
    // Add the test case to the suite
    suite_add_tcase(s, tc_core);
    
    return s;
}
// Main function to run all tests
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }
    
    // Create the test suite and runner
    Suite *s = password_suite();
    SRunner *sr = srunner_create(s);
    
    // Run the tests
    srunner_run_all(sr, CK_NORMAL);
    
    // Get the number of failed tests
    int number_failed = srunner_ntests_failed(sr);
    
    // Clean up
    srunner_free(sr);
    
    return (number_failed == 0) ? 0 : 1;
}