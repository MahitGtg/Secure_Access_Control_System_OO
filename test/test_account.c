#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sodium.h>
#include "../src/account.h"
#include "../src/logging.h"

// Test fixtures
static account_t *test_acc;

void setup(void)
{
    // Create a test account before each test
    test_acc = (account_t *)malloc(sizeof(account_t));
    memset(test_acc, 0, sizeof(account_t));
    strcpy(test_acc->userid, "testuser");
    strcpy(test_acc->email, "test@example.com");
}

void teardown(void)
{
    free(test_acc);
    test_acc = NULL;
}

// Helper to create a dummy account with a known password
void setup_account(account_t *acc, const char *password)
{
    memset(acc, 0, sizeof(account_t));
    strncpy(acc->userid, "testuser", USER_ID_LENGTH - 1);
    strncpy(acc->email, "test@example.com", EMAIL_LENGTH - 1);

    // Fix the truncation warning
    strncpy(acc->birthdate, "2000-01-01", BIRTHDATE_LENGTH - 1);
    acc->birthdate[BIRTHDATE_LENGTH - 1] = '\0'; // Ensure null-termination

    if (!account_update_password(acc, password))
    {
        fprintf(stderr, "Failed to set initial password\n");
    }
}

// Testing email validation - valid email
START_TEST(test_email_valid)
{
    account_set_email(test_acc, "new@example.com");
    ck_assert_str_eq(test_acc->email, "new@example.com");
}
END_TEST

// Testing email validation - invalid email (with space)
START_TEST(test_email_invalid_space)
{
    char original_email[EMAIL_LENGTH];
    strncpy(original_email, test_acc->email, EMAIL_LENGTH);

    account_set_email(test_acc, "invalid email@example.com");

    // Email should not be changed if invalid
    ck_assert_str_eq(test_acc->email, original_email);
}
END_TEST

// Testing email validation - very long email
START_TEST(test_email_too_long)
{
    char original_email[EMAIL_LENGTH];
    strncpy(original_email, test_acc->email, EMAIL_LENGTH);

    // Try to set an email that's too long
    char long_email[EMAIL_LENGTH + 10];
    memset(long_email, 'a', EMAIL_LENGTH + 9);
    long_email[EMAIL_LENGTH + 9] = '\0';

    account_set_email(test_acc, long_email);

    // Email should not be changed if too long
    ck_assert_str_eq(test_acc->email, original_email);
}
END_TEST

// Testing account ban status
START_TEST(test_ban_status)
{
    // Should not be banned by default
    ck_assert(!account_is_banned(test_acc));

    // Setting ban to future time
    time_t future = time(NULL) + 3600; // 1 hour in future
    account_set_unban_time(test_acc, future);
    ck_assert(account_is_banned(test_acc));

    // Setting ban to past time
    time_t past = time(NULL) - 3600; // 1 hour in past
    account_set_unban_time(test_acc, past);
    ck_assert(!account_is_banned(test_acc));

    // Setting ban to 0 (no ban)
    account_set_unban_time(test_acc, 0);
    ck_assert(!account_is_banned(test_acc));
}
END_TEST

// Test account expiration status
START_TEST(test_expiration_status)
{
    // Should not be expired by default
    ck_assert(!account_is_expired(test_acc));

    // Setting expiration to future time
    time_t future = time(NULL) + 3600; // 1 hour in future
    account_set_expiration_time(test_acc, future);
    ck_assert(!account_is_expired(test_acc));

    // Setting expiration to past time
    time_t past = time(NULL) - 3600; // 1 hour in past
    account_set_expiration_time(test_acc, past);
    ck_assert(account_is_expired(test_acc));

    // Setting expiration to 0 (no expiration)
    account_set_expiration_time(test_acc, 0);
    ck_assert(!account_is_expired(test_acc));
}
END_TEST

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

// Test account creation with valid input
START_TEST(test_account_create_valid)
{
    account_t *acc = account_create("user1", "Password123!", "user1@example.com", "2000-01-01");
    ck_assert_ptr_nonnull(acc);
    ck_assert_str_eq(acc->userid, "user1");
    ck_assert_str_eq(acc->email, "user1@example.com");
    ck_assert_str_eq(acc->birthdate, "2000-01-01");
    ck_assert(acc->password_hash[0] != '\0');
    account_free(acc);
}
END_TEST

// Test account creation with NULL arguments
START_TEST(test_account_create_null)
{
    ck_assert_ptr_null(account_create(NULL, "pw", "e", "b"));
    ck_assert_ptr_null(account_create("u", NULL, "e", "b"));
    ck_assert_ptr_null(account_create("u", "pw", NULL, "b"));
    ck_assert_ptr_null(account_create("u", "pw", "e", NULL));
}
END_TEST

// Test account creation with empty string arguments
START_TEST(test_account_create_empty)
{
    ck_assert_ptr_null(account_create("", "pw", "e", "b"));
    ck_assert_ptr_null(account_create("u", "", "e", "b"));
    ck_assert_ptr_null(account_create("u", "pw", "", "b"));
    ck_assert_ptr_null(account_create("u", "pw", "e", ""));
}
END_TEST

// Test account_free with NULL
START_TEST(test_account_free_null)
{
    account_free(NULL); 
}
END_TEST


// Test account creation with valid input (birthdate memcpy check)
START_TEST(test_account_create_birthdate_memcpy)
{
    account_t *acc = account_create("bob", "Password123!", "bob.smith@example.com", "1990-01-01");
    ck_assert_ptr_nonnull(acc);
    // Check that birthdate is copied exactly, no null terminator
    char expected[11] = "1990-01-01";
    ck_assert(memcmp(acc->birthdate, expected, 10) == 0);
    account_free(acc);
}
END_TEST

// Test freeing an account and double free safety
START_TEST(test_account_free_double)
{
    account_t *acc = account_create("alice", "Password123!", "alice@example.com", "2001-12-31");
    ck_assert_ptr_nonnull(acc);
    account_free(acc);
    // Note: We can't call account_free on acc again as it's now a dangling pointer
    // This would be a test for a double-free vulnerability which we want to avoid
    // Instead, we can test that it's safe to free NULL
    account_free(NULL);
}
END_TEST

// Setup the test suite
Suite *account_suite(void)
{
    Suite *s = suite_create("Account");

    // Create test cases
    TCase *tc_email = tcase_create("Email");
    TCase *tc_status = tcase_create("Status");
    TCase *tc_password = tcase_create("Password");

    // Set timeout for password tests (since they use sodium)
    tcase_set_timeout(tc_password, 60); // Set timeout to 60 seconds

    // Add email tests
    tcase_add_checked_fixture(tc_email, setup, teardown);
    tcase_add_test(tc_email, test_email_valid);
    tcase_add_test(tc_email, test_email_invalid_space);
    tcase_add_test(tc_email, test_email_too_long);
    suite_add_tcase(s, tc_email);

    // Add status tests
    tcase_add_checked_fixture(tc_status, setup, teardown);
    tcase_add_test(tc_status, test_ban_status);
    tcase_add_test(tc_status, test_expiration_status);
    suite_add_tcase(s, tc_status);

    // Add password tests
    tcase_add_test(tc_password, test_validate_password);
    tcase_add_test(tc_password, test_update_password);
    tcase_add_test(tc_password, test_account_create_valid);
    tcase_add_test(tc_password, test_account_create_null);
    tcase_add_test(tc_password, test_account_create_empty);
    tcase_add_test(tc_password, test_account_free_null);
    tcase_add_test(tc_password, test_account_create_birthdate_memcpy);
    tcase_add_test(tc_password, test_account_free_double);
    suite_add_tcase(s, tc_password);

    return s;
}

// Main function for running tests
int main(void)
{
    // Initialize sodium library
    if (sodium_init() < 0)
    {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    // Create and run test suite
    Suite *s = account_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}