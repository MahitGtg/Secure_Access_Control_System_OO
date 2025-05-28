# Oblivionaire Online - Access Control System

A secure authentication system for the fictional MMORPG "Oblivionaire Online" - developed for CITS3007 Secure Coding at UWA.

## Overview

This project implements a critical security component for a post-apocalyptic MMORPG, handling:

- **Player Authentication** - Secure login with Argon2id password hashing
- **Session Management** - Secure session handling with timeouts
- **Account Security** - Ban management and brute-force protection
- **Admin Operations** - Staff tools for account management

## Quick Start

### Prerequisites
- Ubuntu/Debian Linux
- GCC with C11 support

### Build & Run
```bash
# Install dependencies
make install-dependencies

# Build project
make all

# Run tests
make test

# Memory safety check
make memcheck
```

## Security Features

✅ **Argon2id Password Hashing** - Industry-standard secure password storage  
✅ **Input Validation** - Comprehensive validation preventing injection attacks  
✅ **Thread Safety** - Mutex protection for concurrent access  
✅ **Memory Safety** - Secure memory wiping, overflow protection  
✅ **Rate Limiting** - Brute force attack mitigation  
✅ **Audit Logging** - Complete security event tracking  

## Project Structure

```
src/
├── account.c/h        # Account management & password security
├── login.c/h          # Authentication logic & session handling
├── db.h               # Database interface
└── logging.h          # Security logging

test/
├── test_account.c     # Unit tests for account functions
├── test_login.c       # Authentication tests
└── fuzz/              # Security fuzzing tests
```

## Testing

### Unit Testing
```bash
make test              # Run all tests with sanitizers
```

### Security Testing
```bash
make memcheck          # Valgrind memory analysis
./run_fuzzers.sh       # Automated vulnerability discovery
```

### Static Analysis
```bash
cppcheck --enable=all src/account.c src/login.c
```

## Key Implementation Details

### Password Security
- **Argon2id hashing** with secure salt generation
- **Complexity requirements** enforced (8+ chars, mixed character classes)
- **Memory protection** - passwords wiped after use
- **Timing attack resistance** - constant-time verification

### Authentication Flow
1. User credentials validated against stored Argon2id hash
2. Account status checked (banned/expired/locked)
3. Login attempts tracked for rate limiting
4. Secure session created with configurable timeout
5. All events logged for security audit

### Thread Safety
- Mutex protection for all shared account data
- Atomic operations for login counters
- Safe concurrent access to session data

## Development

### Coding Standards
- C11 standard with strict compiler warnings
- Memory safety with AddressSanitizer/UBSan
- Comprehensive error handling and logging
- Security-first design principles

### CI/CD Pipeline
- Automated builds on GitHub Actions
- Memory leak detection with Valgrind
- Static analysis with Cppcheck and Clang
- Security fuzzing integration

## Common Commands

```bash
# Development
make clean             # Clean build artifacts
make sanitize          # Build with sanitizers enabled
make docs              # Generate documentation

# Security Testing
FUZZ_TIME=300 ./run_fuzzers.sh    # 5-minute fuzzing session
make run-fuzz-password             # Fuzz password handling
```

## Performance

- **Password Hashing**: ~200ms (intentionally slow for security)
- **Login Validation**: <10ms average
- **Memory Usage**: <1MB per session
- **Thread Contention**: Minimal lock overhead

## Contributors

- **Mahit Gupta** (23690265)
- **Aleksandra Lozyk** (23032563) 
- **Jared Teo** (22987324)

## References

- [OWASP Authentication Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [libsodium Cryptography](https://doc.libsodium.org/)
- [SEI CERT C Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)

---

*CITS3007 Project - University of Western Australia*
