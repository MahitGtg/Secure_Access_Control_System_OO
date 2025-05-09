#include "token.h"
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#define TOKEN_BYTES   32
#define TOKEN_HEXLEN (TOKEN_BYTES * 2)

char *generate_session_token(void) {
    char *token = malloc(TOKEN_HEXLEN + 1);
    if (!token) return NULL;

    unsigned char buf[TOKEN_BYTES];
    ssize_t rd = -1;

    // Try to read cryptographically secure random bytes
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        rd = read(fd, buf, TOKEN_BYTES);
        close(fd);
    }

    // Fallback to rand() if /dev/urandom failed or read too few bytes
    static int seeded = 0;
    if (rd != TOKEN_BYTES) {
        if (!seeded) {
            srand((unsigned)time(NULL) ^ getpid());
            seeded = 1;
        }
        for (int i = 0; i < TOKEN_BYTES; i++) {
            buf[i] = (unsigned char)(rand() & 0xFF);
        }
    }

    // Hex-encode into the token string
    for (int i = 0; i < TOKEN_BYTES; i++) {
        sprintf(&token[i * 2], "%02x", buf[i]);
    }
    token[TOKEN_HEXLEN] = '\0';
    return token;
}