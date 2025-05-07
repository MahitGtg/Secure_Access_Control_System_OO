// DO NOT SUBMIT THIS FILE
//
// When submitting your project, this file will be overwritten
// by the automated build and test system.
//
// You can replace these stub implementations with your own code,
// if you wish.

// allow access to FILE-based IO (e.g. fprintf) in this translation unit
#define CITS3007_PERMISSIVE

#include "logging.h"
#include "db.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "banned.h"


/**
 * Abort immediately for unrecoverable errors /
 * invalid program state.
 * 
 * Arguments:
 * - msg: message to log before aborting
 * 
 * This function should not return.
 */
static void panic(const char *msg) {
  fprintf(stderr, "PANIC: %s\n", msg);
  abort();
}

// Global mutex for logging
// This mutex is used to ensure that log messages are printed in a thread-safe manner.
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_message(log_level_t level, const char *fmt, ...) {
  pthread_mutex_lock(&log_mutex);

  va_list args;
  va_start(args, fmt);
  switch (level) {
    case LOG_DEBUG:
      fprintf(stderr, "DEBUG: ");
      break;
    case LOG_INFO:
      fprintf(stdout, "INFO: ");
      break;
    case LOG_WARN:
      fprintf(stderr, "WARNING: ");
      break;
    case LOG_ERROR:
      fprintf(stderr, "ERROR: ");
      break;
    default:
      panic("Invalid log level");
      break;
  }
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");  // newline, optional
  va_end(args);

  pthread_mutex_unlock(&log_mutex);
}


bool account_lookup_by_userid(const char *userid, account_t *acc) {
  // This is a stub function. In a real implementation, this function would
  // query a database to find the account by user ID.
  // This implementation returns true and fills in a valid struct for userid "bob",
  // and returns false for all other user IDs.

  // Arguments must be non-null or behaviour is undefined; we choose to
  // abort in this case.
  if (!userid || !acc) {
    panic("Invalid arguments to account_lookup_by_userid");
  }

  // Example of a simple lookup. Note that no valid hashed password is set.
  // userid must be a valid, null-terminated string.
  // (Note that it is impossible in C for a function to check whether a string has been
  // properly null-terminated; this is always the responsibility of the caller.)
  if (strncmp(userid, "bob", USER_ID_LENGTH) == 0) {
    account_t bob_acc = { 0 };

    strcpy(bob_acc.userid, "bob");
    strcpy(bob_acc.email, "bob.smith@example.com");
    memcpy(bob_acc.birthdate, "1990-01-01", BIRTHDATE_LENGTH);
    *acc = bob_acc;
    return true;
  }
  return false;
}

