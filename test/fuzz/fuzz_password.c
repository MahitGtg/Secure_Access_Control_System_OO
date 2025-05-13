// test/fuzz/fuzz_password.c
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../../src/account.h"
#include "../../src/logging.h"

void log_message(log_level_t level, const char *fmt, ...)
{
    // Silent during fuzzing
    (void)level;
    (void)fmt;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0)
        return 0;

    // Ensure we have a null-terminated string
    char *password = (char *)malloc(size + 1);
    if (!password)
        return 0;

    memcpy(password, data, size);
    password[size] = '\0';

    // Create a test account
    account_t acc;
    memset(&acc, 0, sizeof(account_t));

    // Test password update
    account_update_password(&acc, password);

    // Test password validation
    account_validate_password(&acc, password);

    free(password);
    return 0;
}
