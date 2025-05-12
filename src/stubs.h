#ifndef STUBS_H
#define STUBS_H

#include "account.h"
#include "login.h"

void account_record_login_failure(account_t *acct);
void account_record_login_success(account_t *acct, ip4_addr_t client_ip);
char *generate_session_token(void);

#endif
