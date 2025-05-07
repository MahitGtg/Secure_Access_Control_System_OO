#ifndef TOKEN_H
#define TOKEN_H

/**
 * generate_session_token
 *
 * Produces a newly allocated, hex‐encoded random string of length 64 (32 bytes).
 * Caller must free() the returned pointer.
 *
 * Preconditions:
 *   - None.
 *
 * Returns:
 *   - Pointer to a malloc()’d C-string on success.
 *   - NULL on allocation or I/O failure.
 */
char *generate_session_token(void);

#endif // TOKEN_H
