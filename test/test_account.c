#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sodium.h>
#include <limits.h>
#include "../src/account.h"
#include "../src/logging.h"

/* Define missing check macros */
#ifndef ck_assert_ptr_null
#define ck_assert_ptr_null(ptr) ck_assert_ptr_eq(ptr, NULL)
#endif

#ifndef ck_assert_ptr_nonnull
#define ck_assert_ptr_nonnull(ptr) ck_assert_ptr_ne(ptr, NULL)
#endif

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

    // Fix the truncation warning by using memcpy instead of strncpy
    // since birthdate is exactly 10 chars with no room for null terminator
    memcpy(acc->birthdate, "2000-01-01", BIRTHDATE_LENGTH);

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
    ck_assert(memcmp(acc->birthdate, "2000-01-01", BIRTHDATE_LENGTH) == 0);
    ck_assert(acc->password_hash[0] != '\0');
    account_free(acc);
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
    // This test passes if it doesn't crash
}
END_TEST

// Test account creation with valid input (birthdate memcpy check)
START_TEST(test_account_create_birthdate_memcpy)
{
    account_t *acc = account_create("bob", "Password123!", "bob.smith@example.com", "1990-01-01");
    ck_assert_ptr_nonnull(acc);
    // Check that birthdate is copied exactly, no null terminator
    const char expected[11] = "1990-01-01";
    ck_assert(memcmp(acc->birthdate, expected, BIRTHDATE_LENGTH) == 0);
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

// Test login success recording
START_TEST(test_record_login_success)
{
    // Create a test account
    account_t acc;
    memset(&acc, 0, sizeof(account_t));
    strncpy(acc.userid, "testuser", USER_ID_LENGTH - 1);

    // Set initial values
    acc.login_count = 5;
    acc.login_fail_count = 3;
    acc.last_login_time = 0;
    acc.last_ip = 0;

    // Test IP address (192.168.1.100)
    ip4_addr_t test_ip = (192U << 24) | (168U << 16) | (1U << 8) | 100U;

    // Record login success
    account_record_login_success(&acc, test_ip);

    // Verify the login count was incremented
    ck_assert_uint_eq(acc.login_count, 6);

    // Verify the login failure count was reset
    ck_assert_uint_eq(acc.login_fail_count, 0);

    // Verify the last login time was set (should be recent)
    time_t current_time = time(NULL);
    ck_assert(acc.last_login_time >= (time_t)(current_time - 5));
    ck_assert(acc.last_login_time <= (time_t)(current_time + 5));

    // Verify the last IP was recorded correctly
    ck_assert_uint_eq(acc.last_ip, test_ip);
}
END_TEST

// Test login failure recording
START_TEST(test_record_login_failure)
{
    // Create a test account
    account_t acc;
    memset(&acc, 0, sizeof(account_t));
    strncpy(acc.userid, "testuser", USER_ID_LENGTH - 1);

    // Set initial values
    acc.login_count = 5;
    acc.login_fail_count = 3;

    // Record login failure
    account_record_login_failure(&acc);

    // Verify the login failure count was incremented
    ck_assert_uint_eq(acc.login_fail_count, 4);

    // Verify the login count was reset
    ck_assert_uint_eq(acc.login_count, 0);

    // Test overflow protection
    acc.login_fail_count = UINT_MAX;
    account_record_login_failure(&acc);

    // Verify the login failure count doesn't overflow
    ck_assert_uint_eq(acc.login_fail_count, UINT_MAX);
}
END_TEST

// Test account summary printing
START_TEST(test_account_print_summary)
{
    // Create a test pipe for capturing the output
    int pipefd[2];
    if (pipe(pipefd) == -1)
    {
        ck_abort_msg("Failed to create pipe");
    }

    // Create a test account with known values
    account_t acc;
    memset(&acc, 0, sizeof(account_t));

    strncpy(acc.userid, "testuser", USER_ID_LENGTH - 1);
    strncpy(acc.email, "test@example.com", EMAIL_LENGTH - 1);
    memcpy(acc.birthdate, "2000-01-01", BIRTHDATE_LENGTH);

    acc.login_count = 42;
    acc.login_fail_count = 7;

    // Set a known IP (192.168.1.100)
    acc.last_ip = (192U << 24) | (168U << 16) | (1U << 8) | 100U;

    // Set last login time to a fixed value for testing
    acc.last_login_time = 1620000000; // May 3, 2021

    // Print the summary to the pipe
    bool result = account_print_summary(&acc, pipefd[1]);
    ck_assert_msg(result, "account_print_summary returned false");

    // Close the write end of the pipe
    close(pipefd[1]);

    // Read the output from the pipe
    char buffer[1024];
    ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1);
    ck_assert_int_gt(bytes_read, 0);
    buffer[bytes_read] = '\0';

    // Close the read end of the pipe
    close(pipefd[0]);

    // Check that the output contains the expected information
    ck_assert_msg(strstr(buffer, "testuser") != NULL, "Output missing userid");
    ck_assert_msg(strstr(buffer, "test@example.com") != NULL, "Output missing email");
    ck_assert_msg(strstr(buffer, "2000-01-01") != NULL, "Output missing birthdate");
    ck_assert_msg(strstr(buffer, "42") != NULL, "Output missing login count");
    ck_assert_msg(strstr(buffer, "7") != NULL, "Output missing login failure count");
    ck_assert_msg(strstr(buffer, "192.168.1.100") != NULL, "Output missing IP address");

    // The time string format might vary, but should at least contain "2021"
    ck_assert_msg(strstr(buffer, "2021") != NULL, "Output missing or incorrect timestamp");
}
END_TEST

// Test account summary with invalid file descriptor
START_TEST(test_account_print_summary_invalid_fd)
{
    account_t acc;
    memset(&acc, 0, sizeof(account_t));

    // This should return false, not crash
    bool result = account_print_summary(&acc, -1);
    ck_assert_msg(!result, "account_print_summary with invalid fd should return false");
}
END_TEST

// Helper function for safe IP address construction
static ip4_addr_t safe_construct_ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
}

// Test IP address construction safety
START_TEST(test_ip_address_construction)
{
    // Test edge cases that would overflow with signed int
    ip4_addr_t ip1 = safe_construct_ip(255, 255, 255, 255); // Max IP
    ck_assert_uint_eq(ip1, 0xFFFFFFFF);

    ip4_addr_t ip2 = safe_construct_ip(128, 0, 0, 0); // High bit set
    ck_assert_uint_eq(ip2, 0x80000000);

    // Test recording these IPs
    account_t acc;
    memset(&acc, 0, sizeof(account_t));

    account_record_login_success(&acc, ip1);
    ck_assert_uint_eq(acc.last_ip, ip1);

    account_record_login_success(&acc, ip2);
    ck_assert_uint_eq(acc.last_ip, ip2);
}
END_TEST

// Test password handling safety
START_TEST(test_password_handling_safety)
{
    account_t acc;
    memset(&acc, 0, sizeof(account_t));

    // Test NULL password
    ck_assert(!account_update_password(&acc, NULL));

    // Test empty password
    ck_assert(!account_update_password(&acc, ""));

    // Test very long password (should be rejected before reaching libsodium)
    char long_pw[10000];
    memset(long_pw, 'a', sizeof(long_pw) - 1);
    long_pw[sizeof(long_pw) - 1] = '\0';
    ck_assert(!account_update_password(&acc, long_pw));

    // Test password with null bytes
    const char pw_with_null[] = "Pass\0word";
    ck_assert(!account_update_password(&acc, pw_with_null));

    // Test password with invalid UTF-8
    unsigned char invalid_utf8[] = {0xFF, 0xFE, 0xFD, 0x00};
    ck_assert(!account_update_password(&acc, (char *)invalid_utf8));
}
END_TEST

// In the account_suite function, add these test cases:
void add_login_tests_to_suite(Suite *s)
{
    // Create a test case for login recording functions
    TCase *tc_login = tcase_create("Login");
    tcase_add_test(tc_login, test_record_login_success);
    tcase_add_test(tc_login, test_record_login_failure);
    suite_add_tcase(s, tc_login);

    // Create a test case for account summary
    TCase *tc_summary = tcase_create("Summary");
    tcase_add_test(tc_summary, test_account_print_summary);
    tcase_add_test(tc_summary, test_account_print_summary_invalid_fd);
    suite_add_tcase(s, tc_summary);
}

void add_security_tests_to_suite(Suite *s)
{
    TCase *tc_security = tcase_create("Security");
    tcase_add_test(tc_security, test_ip_address_construction);
    tcase_add_test(tc_security, test_password_handling_safety);
    suite_add_tcase(s, tc_security);
}

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
    tcase_add_test(tc_password, test_account_create_empty);
    tcase_add_test(tc_password, test_account_free_null);
    tcase_add_test(tc_password, test_account_create_birthdate_memcpy);
    tcase_add_test(tc_password, test_account_free_double);
    suite_add_tcase(s, tc_password);

    // Add our new login and summary tests
    add_login_tests_to_suite(s);

    // Add our new security tests
    add_security_tests_to_suite(s);

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