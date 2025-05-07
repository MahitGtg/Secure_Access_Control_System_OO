// Banned functions

#ifndef BANNED_H
#define BANNED_H

// store current diagnostic state, and suppress warnings (we re-enable later).
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
//#pragma GCC diagnostic ignored "-Wmacro-redefined"

#ifndef CITS3007_PERMISSIVE

// unsafe

#pragma GCC poison \
    atof     \
    atoi     \
    atol     \
    atoll    \
    system

#undef alloca

#define alloca DO_NOT_USE_alloca

// alters exit behaviour

#pragma GCC poison \
    atexit          \
    at_quick_exit

// FILE-based IO, direct access to standard error streams

#undef stdin
#undef stdout
#undef stderr

#define stdin  DO_NOT_USE_stdin_USE_LOGGING
#define stdout DO_NOT_USE_stdout_USE_LOGGING
#define stderr DO_NOT_USE_stderr_USE_LOGGING

#undef printf
#define printf  DO_NOT_USE_printf_USE_dprintf_INSTEAD

#undef fprintf
#define fprintf DO_NOT_USE_fprintf_USE_dprintf_OR_write

#undef fscanf
#define fscanf  DO_NOT_USE_fscanf

#undef scanf
#define scanf   DO_NOT_USE_scanf

#pragma GCC poison \
    FILE        \
    fclose      \
    fflush      \
    fopen       \
    freopen     \
    vfprintf    \
    vprintf     \
    vscanf      \
    fgets       \
    fputs       \
    gets        \
    puts        \
    fgetc       \
    fputc       \
    getc        \
    getchar     \
    putc        \
    putchar     \
    ungetc      \
    fread       \
    fwrite      \
    perror      \
    tmpfile     \
    tmpnam

#endif // CITS3007_PERMISSIVE

// Restore diagnostic state
#pragma GCC diagnostic pop

#endif // BANNED_H
