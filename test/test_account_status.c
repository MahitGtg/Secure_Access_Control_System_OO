#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <string.h>
#include <unistd.h>
#include "../src/account.h"
#include "../src/logging.h"

// test fixture setup
static account_t *test_acc;

void setup(void) {
    // create a test account before each test
    test_acc = malloc(sizeof(account_t));
    memset(test_acc, 0, sizeof(account_t));
    strcpy(test_acc->userid, "testuser");
    strcpy(test_acc->email, "test@example.com");
}

void teardown(void) {
    free(test_acc);
    test_acc = NULL;
}

// testing email validation - valid email
START_TEST(test_email_valid) {
    account_set_email(test_acc, "new@example.com");
    ck_assert_str_eq(test_acc->email, "new@example.com");
}
END_TEST

// testing email validation - invalid email (with space)
START_TEST(test_email_invalid_space) {
    char original_email[EMAIL_LENGTH];
    strncpy(original_email, test_acc->email, EMAIL_LENGTH);
    
    account_set_email(test_acc, "invalid email@example.com");
    
    // email should not be changed if invalid
    ck_assert_str_eq(test_acc->email, original_email);
}
END_TEST

// testing account ban status
START_TEST(test_ban_status) {
    // should not be banned by default
    ck_assert(!account_is_banned(test_acc));
    
    // setting ban to future time
    time_t future = time(NULL) + 3600; // 1 hour in future
    account_set_unban_time(test_acc, future);
    ck_assert(account_is_banned(test_acc));
    
    // setting ban to past time
    time_t past = time(NULL) - 3600; // 1 hour in past
    account_set_unban_time(test_acc, past);
    ck_assert(!account_is_banned(test_acc));
    
    // setting ban to 0 (no ban)
    account_set_unban_time(test_acc, 0);
    ck_assert(!account_is_banned(test_acc));
}
END_TEST

// Test account expiration status
START_TEST(test_expiration_status) {
    // should not be expired by default
    ck_assert(!account_is_expired(test_acc));
    
    // setting expiration to future time
    time_t future = time(NULL) + 3600; // 1 hour in future
    account_set_expiration_time(test_acc, future);
    ck_assert(!account_is_expired(test_acc));
    
    // setting expiration to past time
    time_t past = time(NULL) - 3600; // 1 hour in past
    account_set_expiration_time(test_acc, past);
    ck_assert(account_is_expired(test_acc));
    
    // setting expiration to 0 (no expiration)
    account_set_expiration_time(test_acc, 0);
    ck_assert(!account_is_expired(test_acc));
}
END_TEST

// creating test suite
Suite *account_suite(void) {
    Suite *s = suite_create("Account");
    TCase *tc_email = tcase_create("Email");
    TCase *tc_status = tcase_create("Status");
    
    // email tests
    tcase_add_checked_fixture(tc_email, setup, teardown);
    tcase_add_test(tc_email, test_email_valid);
    tcase_add_test(tc_email, test_email_invalid_space);
    suite_add_tcase(s, tc_email);
    
    // status tests
    tcase_add_checked_fixture(tc_status, setup, teardown);
    tcase_add_test(tc_status, test_ban_status);
    tcase_add_test(tc_status, test_expiration_status);
    suite_add_tcase(s, tc_status);
    
    return s;
}

// main function for running tests
int main(void) {
    Suite *s = account_suite();
    SRunner *sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}