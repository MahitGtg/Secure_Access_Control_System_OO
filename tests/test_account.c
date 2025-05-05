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

// Test login tracking
START_TEST(test_login_tracking) {
    // initial counts should be 0
    ck_assert_int_eq(test_acc->login_count, 0);
    ck_assert_int_eq(test_acc->login_fail_count, 0);
    
    // recording success
    account_record_login_success(test_acc, 0x12345678);
    ck_assert_int_eq(test_acc->login_count, 1);
    ck_assert_int_eq(test_acc->login_fail_count, 0);
    ck_assert_int_eq(test_acc->last_ip, 0x12345678);
    
    // recording failure
    account_record_login_failure(test_acc);
    ck_assert_int_eq(test_acc->login_count, 0); // reset on failure
    ck_assert_int_eq(test_acc->login_fail_count, 1);
    
    // recording another success
    account_record_login_success(test_acc, 0x87654321);
    ck_assert_int_eq(test_acc->login_count, 1);
    ck_assert_int_eq(test_acc->login_fail_count, 0); // reset on success
    ck_assert_int_eq(test_acc->last_ip, 0x87654321);
}
END_TEST

// Test account summary printing
START_TEST(test_account_summary) {
    // creating a pipe for testing output
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        ck_abort_msg("Failed to create pipe");
    }
    
    // printing account summary to pipe
    bool result = account_print_summary(test_acc, pipefd[1]);
    ck_assert(result);
    
    // closing write end
    close(pipefd[1]);
    
    // reading from pipe
    char buffer[1024] = {0};
    ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1);
    close(pipefd[0]);
    
    ck_assert_int_gt(bytes_read, 0);
    ck_assert(strstr(buffer, "testuser") != NULL);
    ck_assert(strstr(buffer, "test@example.com") != NULL);
}
END_TEST

// creating test suite
Suite *account_suite(void) {
    Suite *s = suite_create("Account");
    TCase *tc_email = tcase_create("Email");
    TCase *tc_status = tcase_create("Status");
    TCase *tc_login = tcase_create("Login");
    TCase *tc_summary = tcase_create("Summary");
    
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
    
    // login tests
    tcase_add_checked_fixture(tc_login, setup, teardown);
    tcase_add_test(tc_login, test_login_tracking);
    suite_add_tcase(s, tc_login);
    
    // summary tests
    tcase_add_checked_fixture(tc_summary, setup, teardown);
    tcase_add_test(tc_summary, test_account_summary);
    suite_add_tcase(s, tc_summary);
    
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