// DO NOT SUBMIT THIS FILE
//
// When submitting your project, this file will be overwritten
// by the automated build and test system.

#include "login.h"
#include "account.h"

#include <stdlib.h>
#include <unistd.h>

// bogus implementation of main that links in all account and login
// functions. You can delete this file and replace it with your own main
// function(s).
int main(int argc, char *argv[]) {
  (void) argc;
  (void) argv;

  account_t *acc = account_create("", "", "", "");
  account_free(acc);
  bool res = account_validate_password(acc, "");
  res = account_update_password(acc, "");
  account_record_login_success(acc, 0);
  account_record_login_failure(acc);
  res = account_is_banned(acc);
  res = account_is_expired(acc);
  account_set_unban_time(acc, 0);
  account_set_expiration_time(acc, 0);
  account_set_email(acc, "");
  (void) account_print_summary(acc, STDOUT_FILENO);
  (void) res;
  handle_login("", "", 0, 0, STDOUT_FILENO, STDOUT_FILENO, NULL);
  return 0;
}

