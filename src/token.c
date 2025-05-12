#include "token.h"
#include "logging.h"
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>

#define TOKEN_BYTES 32
#define TOKEN_HEXLEN (TOKEN_BYTES * 2)

/**
 * Generates a cryptographically secure random session token.
 *
 * This function:
 * - Tries to use libsodium's random number generator (preferred)
 * - Falls back to /dev/urandom if libsodium fails
 * - Has a final fallback to a seeded rand() if all else fails
 * - Returns a 64-character hex-encoded string (representing 32 random bytes)
 *
 * @return Pointer to a malloc'd string containing the token, NULL on failure
 */
char *generate_session_token(void)
{
    char *token = (char *)malloc(TOKEN_HEXLEN + 1);
    if (!token)
    {
        log_message(LOG_ERROR, "Failed to allocate memory for session token");
        return NULL;
    }

    unsigned char buf[TOKEN_BYTES] = {0};
    bool generated = false;

    // Try libsodium first (most secure)
    if (sodium_init() >= 0)
    {
        randombytes_buf(buf, TOKEN_BYTES);
        generated = true;
        log_message(LOG_DEBUG, "Generated token using libsodium");
    }
    // If libsodium fails, try /dev/urandom
    else
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0)
        {
            ssize_t rd = read(fd, buf, TOKEN_BYTES);
            close(fd);

            if (rd == TOKEN_BYTES)
            {
                generated = true;
                log_message(LOG_DEBUG, "Generated token using /dev/urandom");
            }
        }
    }

    // Last resort: use rand() (less secure)
    if (!generated)
    {
        static int seeded = 0;
        if (!seeded)
        {
            unsigned int seed = (unsigned int)time(NULL);
            seed ^= (unsigned int)getpid();

            // Additional entropy if available
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd >= 0)
            {
                unsigned int extra_seed;
                if (read(fd, &extra_seed, sizeof(extra_seed)) == sizeof(extra_seed))
                {
                    seed ^= extra_seed;
                }
                close(fd);
            }

            srand(seed);
            seeded = 1;
        }

        for (int i = 0; i < TOKEN_BYTES; i++)
        {
            buf[i] = (unsigned char)(rand() & 0xFF);
        }
        log_message(LOG_WARN, "Generated token using rand() - less secure");
    }

    // Convert binary data to hex string
    if (sodium_init() >= 0)
    {
        // Use libsodium's hex encoder if available (constant-time)
        sodium_bin2hex(token, TOKEN_HEXLEN + 1, buf, TOKEN_BYTES);
    }
    else
    {
        // Fallback to sprintf if necessary
        for (int i = 0; i < TOKEN_BYTES; i++)
        {
            sprintf(&token[i * 2], "%02x", buf[i]);
        }
        token[TOKEN_HEXLEN] = '\0';
    }

    // Securely wipe the buffer containing the random bytes
    if (sodium_init() >= 0)
    {
        sodium_memzero(buf, TOKEN_BYTES);
    }
    else
    {
        memset(buf, 0, TOKEN_BYTES);
    }

    return token;
}