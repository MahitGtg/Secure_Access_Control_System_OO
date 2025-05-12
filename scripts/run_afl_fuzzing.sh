#!/bin/bash
# run_afl_fuzzing.sh - Script to set up and run AFL fuzzing for Oblivionaire Online

#exit on errors but debug first
set -e

#configuration
PROJ_DIR="$(dirname "$(readlink -f "$0")")"
PROJ_DIR="$(dirname "$PROJ_DIR")" #parent directory of scripts
AFL_INPUT_DIR="$PROJ_DIR/afl_input"
AFL_OUTPUT_DIR="$PROJ_DIR/afl_output"
FUZZER_TARGET="$PROJ_DIR/bin/afl_fuzzer"
PARALLEL_JOBS=1  #reduced to 1 for debugging
TIMEOUT=1000

#colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' #no color

echo -e "${GREEN}=== Oblivionaire Online AFL Fuzzing Setup ===${NC}"
echo -e "${YELLOW}Project directory: $PROJ_DIR${NC}"

#check if afl is installed
if ! command -v afl-gcc &> /dev/null; then
    echo -e "${RED}Error: AFL not found! Please install AFL first.${NC}"
    echo "On Ubuntu/Debian: sudo apt-get install afl++"
    exit 1
fi

#create directories
mkdir -p "$AFL_INPUT_DIR"
mkdir -p "$AFL_OUTPUT_DIR"
mkdir -p "$PROJ_DIR/bin"

echo -e "${GREEN}=== Creating test cases ===${NC}"

#create initial test cases
echo -e "user1\0password123\0user1@example.com\02000-01-01" > "$AFL_INPUT_DIR/valid.bin"
echo -e "\0\0\0\0" > "$AFL_INPUT_DIR/all_null.bin"
echo -e "verylongusernamethatexceedsmaxlength\0p\0e\01999-01-01" > "$AFL_INPUT_DIR/long_user.bin"
echo -e "user\0verylongpasswordthatexceedsmaxlength\0e\01999-01-01" > "$AFL_INPUT_DIR/long_pass.bin"
echo -e "user\0pass\0invalid-email\01999-01-01" > "$AFL_INPUT_DIR/invalid_email.bin"
echo -e "user\0pass\0email@test.com\0invalid-date" > "$AFL_INPUT_DIR/invalid_date.bin"
echo -e "user\0pass\0email@test.com\02099-02-30" > "$AFL_INPUT_DIR/edge_date.bin"

echo -e "${GREEN}=== Setting up for AFL instrumented build ===${NC}"

#configure core dump handling
echo -e "${YELLOW}Setting up core dump pattern for AFL...${NC}"
echo core | sudo tee /proc/sys/kernel/core_pattern &> /dev/null || echo -e "${YELLOW}Could not set core pattern. You might need sudo privileges.${NC}"
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor &> /dev/null 2>&1 || echo -e "${YELLOW}Could not set CPU scaling governor to performance. This is fine on some systems.${NC}"

#create the fixed afl_fuzzing.c file
echo -e "${GREEN}Creating AFL fuzzing harness...${NC}"
cat > "$PROJ_DIR/src/afl_fuzzing.c" << 'EOF'
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include "account.h"
#include "login.h"
#include "db.h"
#include "logging.h"
#include <sodium.h>
#include "banned.h"

//afl persistent mode requires these declarations
#ifdef __AFL_HAVE_MANUAL_CONTROL
extern unsigned int __afl_persistent_loop(unsigned int);
#else
//if not compiled with afl, create a stub function for testing
static unsigned int __afl_persistent_loop(unsigned int count) {
    static unsigned int counter = 0;
    return counter++ < count ? 1 : 0;
}
#endif

//function to parse input and extract test data
static bool parse_input(const char* input, size_t input_size, 
                        char* userid, char* password, char* email, char* birthdate) {
    if (!input || input_size < 4) {
        return false;
    }
    
    //split input into 4 parts using simple delimiter-based parsing
    //format expected: userid\0password\0email\0birthdate
    size_t pos = 0;
    size_t field = 0;
    size_t field_pos = 0;
    
    while (pos < input_size && field < 4) {
        char current = input[pos++];
        
        //use null bytes or newlines as field separators
        if (current == '\0' || current == '\n') {
            //terminate current field
            switch (field) {
                case 0: userid[field_pos] = '\0'; break;
                case 1: password[field_pos] = '\0'; break;
                case 2: email[field_pos] = '\0'; break;
                case 3: birthdate[field_pos] = '\0'; break;
            }
            
            //move to next field
            field++;
            field_pos = 0;
        } else {
            // Add character to current field, respecting maximum lengths
            switch (field) {
                case 0:
                    if (field_pos < USER_ID_LENGTH - 1)
                        userid[field_pos++] = current;
                    break;
                case 1:
                    if (field_pos < HASH_LENGTH - 1)
                        password[field_pos++] = current;
                    break;
                case 2:
                    if (field_pos < EMAIL_LENGTH - 1)
                        email[field_pos++] = current;
                    break;
                case 3:
                    if (field_pos < BIRTHDATE_LENGTH - 1)
                        birthdate[field_pos++] = current;
                    break;
            }
        }
    }
    
    // Make sure all fields are properly terminated
    userid[field_pos >= USER_ID_LENGTH ? USER_ID_LENGTH - 1 : field_pos] = '\0';
    password[field_pos >= HASH_LENGTH ? HASH_LENGTH - 1 : field_pos] = '\0';
    email[field_pos >= EMAIL_LENGTH ? EMAIL_LENGTH - 1 : field_pos] = '\0';
    
    // Birthdate needs special handling - it must be exactly 10 bytes
    if (field == 3 && field_pos <= BIRTHDATE_LENGTH) {
        // If not enough characters for birthdate, use a valid one
        if (field_pos < 10) {
            memcpy(birthdate, "2000-01-01", 10);
        }
        return true;
    }
    
    // Default birthdate if not enough fields
    memcpy(birthdate, "2000-01-01", 10);
    return field >= 3; // Need at least 3 fields for valid test case
}

// Main fuzzing harness for account_create and password validation
int main(int argc, char *argv[]) {
    // Initialize random seed for non-AFL testing
    srand((unsigned int)time(NULL));
    
    // Buffers for test data
    char userid[USER_ID_LENGTH];
    char password[HASH_LENGTH];
    char email[EMAIL_LENGTH];
    char birthdate[BIRTHDATE_LENGTH + 1]; // +1 for null terminator

    // Buffer for reading AFL input
    char input_buffer[4096];
    
    // Set up file descriptors (avoid using stdin/stdout due to AFL instrumentation)
    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null == -1) {
        // Use log_message instead of perror
        log_message(LOG_ERROR, "Failed to open /dev/null: %s", strerror(errno));
        return 1;
    }
    
    // Initialize sodium (needed for password hashing)
    if (sodium_init() < 0) {
        // Use log_message instead of fprintf
        log_message(LOG_ERROR, "Failed to initialize libsodium");
        close(dev_null);
        return 1;
    }
    
    // Main AFL persistent loop
    // This allows AFL to run the fuzzing target multiple times without restarting the process
    while (__afl_persistent_loop(1000)) {
        // Reset buffers
        memset(userid, 0, USER_ID_LENGTH);
        memset(password, 0, HASH_LENGTH);
        memset(email, 0, EMAIL_LENGTH);
        memset(birthdate, 0, BIRTHDATE_LENGTH + 1);
        memset(input_buffer, 0, sizeof(input_buffer));
        
        // Read input from AFL
        ssize_t bytes_read = read(STDIN_FILENO, input_buffer, sizeof(input_buffer) - 1);
        if (bytes_read <= 0) {
            continue; // Skip empty input
        }
        
        // Ensure null termination
        input_buffer[bytes_read] = '\0';
        
        // Parse input
        if (!parse_input(input_buffer, (size_t)bytes_read, userid, password, email, birthdate)) {
            continue;
        }
        
        // Target 1: account_create
        account_t* account = account_create(userid, password, email, birthdate);
        
        // Continue fuzzing only if account was created successfully
        if (account) {
            // Target 2: account_validate_password
            account_validate_password(account, password);
            
            // Target 3: account_update_password
            // Use first half of password as new password to test update
            char new_password[HASH_LENGTH/2 + 1];
            size_t password_len = strlen(password);
            size_t half_len = password_len / 2;
            
            if (half_len > 0) {
                strncpy(new_password, password, half_len);
                new_password[half_len] = '\0';
                account_update_password(account, new_password);
            }
            
            // Target 4: account_set_email
            // Use first half of email as new email to test update
            char new_email[EMAIL_LENGTH/2 + 1];
            size_t email_len = strlen(email);
            half_len = email_len / 2;
            
            if (half_len > 0) {
                strncpy(new_email, email, half_len);
                new_email[half_len] = '\0';
                account_set_email(account, new_email);
            }
            
            // Target 5: login handling
            login_session_data_t session;
            handle_login(userid, password, 
                        (ip4_addr_t)(bytes_read & 0xFFFFFFFF), // Use part of input as IP
                        (time_t)bytes_read, // Use input size as timestamp
                        dev_null, // Write output to /dev/null
                        &session);
            
            // Properly clean up to avoid memory leaks
            account_free(account);
        }
    }
    
    close(dev_null);
    return 0;
}
EOF

echo -e "${GREEN}=== Compiling AFL instrumented target ===${NC}"

#change to project directory
cd "$PROJ_DIR"

#clean build artifacts first if make clean is available
if [ -f Makefile ]; then
    make clean || echo -e "${YELLOW}Failed to clean, but continuing...${NC}"
fi

#prevent gcc from being called, use afl-gcc explicitly
echo -e "${GREEN}Directly compiling with AFL instrumentation...${NC}"

#define compilation flags
CFLAGS="-DTESTING"

#attempt to compile directly with afl instrumentation
afl-gcc $CFLAGS -g -I"$PROJ_DIR/src" \
    -o "$FUZZER_TARGET" \
    "$PROJ_DIR/src/afl_fuzzing.c" \
    "$PROJ_DIR/src/account.c" \
    "$PROJ_DIR/src/login.c" \
    "$PROJ_DIR/src/stubs.c" \
    -lsodium -lcheck_pic -pthread -lrt -lm -lsubunit

#verify that the binary was built
if [ ! -f "$FUZZER_TARGET" ]; then
    echo -e "${RED}Error: Failed to build fuzzer target!${NC}"
    exit 1
fi

echo -e "${GREEN}Successfully built AFL fuzzing target!${NC}"

#start afl fuzzing with qemu mode as fallback
echo -e "${GREEN}=== Starting AFL Fuzzing ===${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop fuzzing.${NC}"

#check if we can use qemu mode
if command -v afl-qemu-trace &> /dev/null; then
    QEMU_FLAG="-Q"
    echo -e "${YELLOW}QEMU mode is available. Using it as fallback.${NC}"
else
    QEMU_FLAG=""
    echo -e "${YELLOW}QEMU mode not available. Using standard instrumentation.${NC}"
fi

#first try with normal mode
if [ "$QEMU_FLAG" = "" ]; then
    echo -e "${GREEN}Starting fuzzer in standard mode...${NC}"
    afl-fuzz -i "$AFL_INPUT_DIR" -o "$AFL_OUTPUT_DIR" -m none -- "$FUZZER_TARGET"
else
    echo -e "${GREEN}Starting fuzzer with QEMU mode...${NC}"
    afl-fuzz $QEMU_FLAG -i "$AFL_INPUT_DIR" -o "$AFL_OUTPUT_DIR" -m none -- "$FUZZER_TARGET"
fi