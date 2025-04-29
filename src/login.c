#include "login.h"

login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd, int log_fd,
                            login_session_data_t *session) 
{
  // remove the contents of this function and replace it with your own code.
  (void) userid;
  (void) password;
  (void) client_ip;
  (void) login_time;
  (void) client_output_fd;
  (void) log_fd;
  (void) session;

  return LOGIN_SUCCESS;
}
