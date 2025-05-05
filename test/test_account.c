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
    strncpy(acc->birthdate, "2000-01-01", BIRTHDATE_LENGTH - 1);
    assert(account_update_password(acc, password));
}

void test_validate_password()
{
    account_t acc;
    setup_account(&acc, "TestPass123!");
    // Correct password
    assert(account_validate_password(&acc, "TestPass123!"));
    // Wrong password
    assert(!account_validate_password(&acc, "WrongPass"));
    // Empty password
    assert(!account_validate_password(&acc, ""));
    // Too long password
    char longpw[1100];
    memset(longpw, 'a', 1099);
    longpw[1099] = '\0';
    assert(!account_validate_password(&acc, longpw));
}

void test_update_password()
{
    account_t acc;
    setup_account(&acc, "Start123!");
    // Update to a new valid password
    assert(account_update_password(&acc, "NewPass456!"));
    assert(account_validate_password(&acc, "NewPass456!"));
    assert(!account_validate_password(&acc, "Start123!"));
    // Too short
    assert(!account_update_password(&acc, "aB1!"));
    // Not complex enough
    assert(!account_update_password(&acc, "alllowercase"));
    assert(!account_update_password(&acc, "ALLUPPERCASE"));
    assert(!account_update_password(&acc, "12345678"));
    // Too long
    char longpw[1100];
    memset(longpw, 'a', 1099);
    longpw[1099] = '\0';
    assert(!account_update_password(&acc, longpw));
}

int main()
{
    if (sodium_init() < 0)
    {
        printf("libsodium init failed\n");
        return 1;
    }
    test_validate_password();
    test_update_password();
    printf("All tests passed!\n");
    return 0;
}