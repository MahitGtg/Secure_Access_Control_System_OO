#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

void log_message(log_level_t level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    char timestamp[26];
    ctime_r(&now, timestamp);
    timestamp[24] = '\0'; // remove newline
    
    const char *level_str;
    switch(level) {
        case LOG_ERROR:
            level_str = "ERROR";
            break;
        case LOG_WARN:
            level_str = "WARN";
            break;
        case LOG_INFO:
            level_str = "INFO";
            break;
        default:
            level_str = "UNKNOWN";
    }
    
    fprintf(stderr, "[%s] %s: ", timestamp, level_str);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    
    va_end(args);
}

void panic(const char *msg) {
    log_message(LOG_ERROR, "PANIC: %s", msg);
    abort();
} 