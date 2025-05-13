# DO NOT SUBMIT THIS FILE
#
# When submitting your project, this file will be overwritten
# by the automated build and test system.

###
# Variables
# (can be overridden from command-line)

CC = gcc

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin
TEST_DIR := test

# The target executable.
# This executable is created by linking together all object files
# obtained from a .c file in the `src` directory; so exactly one
# .c file should contain a `main` function.
# Alternative implementations of main can be wrapped in #ifdefs, as
# long as exactly one is compiled; then they can be selected by
# supplying `-D` flags to `make` and thence to the compiler.
# See e.g. `alternate_main.c`
TARGET = $(BIN_DIR)/app

# Find test specification files and their C equivalents
TS_FILES := $(shell find $(SRC_DIR) -name "*.ts")
SRC_FILES := $(shell find $(SRC_DIR) -name "*.c") $(TS_FILES:.ts=.c)

OBJ_FILES := $(SRC_FILES:.c=.o)
# we need to uniq-ify object files to stop .ts and .c versions of tests showing up twice
OBJ_FILES := $(shell echo $(subst $(SRC_DIR),$(BUILD_DIR),$(OBJ_FILES)) | tr ' ' '\n' | sort | uniq)

SRC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAGS := $(addprefix -I, $(SRC_DIRS))

# get compiler flags for installed libraries using pkg-config.
PKG_DEPS := $(shell cat libraries.txt | grep -v "^\#" | xargs)

# Set PKG_CFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the compiler flags for the dependencies
PKG_CFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --cflags $(PKG_DEPS)))

# Set PKG_LDFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the linker flags for the dependencies
PKG_LDFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --libs $(PKG_DEPS)))

# Additional flags for security analysis
DEBUG = -g -fno-omit-frame-pointer
EXTRA_CFLAGS = -Werror=vla -Werror=implicit-function-declaration -fstack-protector-strong
SANITIZER_FLAGS = -fsanitize=address -fsanitize=undefined -fno-sanitize-recover=all
CFLAGS = $(DEBUG) -std=c11 -pedantic-errors -Wall -Wextra -Wshadow -Wconversion -O $(EXTRA_CFLAGS) $(INC_FLAGS) $(PKG_CFLAGS)
LDFLAGS = $(PKG_LDFLAGS)

# Test flags
TEST_CFLAGS = $(CFLAGS) $(SANITIZER_FLAGS)
TEST_LDFLAGS = $(LDFLAGS) -lsodium -lcheck -lsubunit -pthread -lrt -lm

# how to make a .c file from a .ts file
%.c: %.ts
	checkmk $< > $@

###
# Targets

all: $(TARGET)

# Link executable
$(TARGET): $(OBJ_FILES)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJ_FILES) -o $(TARGET) $(LDFLAGS)

# Compile source files

# c
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	./add_banned_header.pl $
	$(CC) $(CFLAGS) $(INC_FLAGS) -MMD -MP -c $< -o $@

# targets for each object file
$(foreach obj_file,$(OBJ_FILES),$(eval $(obj_file):))

# Install dependencies
install-dependencies:
	cat apt-packages.txt | sudo ./scripts/install-deps.sh

# Find all test source files
TEST_SRC := $(wildcard $(TEST_DIR)/test_*.c)

# Extract test names and create test binary names
TEST_NAMES := $(patsubst $(TEST_DIR)/test_%.c,%,$(TEST_SRC))
TEST_BINS := $(patsubst %,test/test_%,$(TEST_NAMES))

# Valgrind-specific test binaries
VALGRIND_TEST_SRC := $(wildcard $(TEST_DIR)/test_*_valgrind.c)
VALGRIND_TEST_NAMES := $(patsubst $(TEST_DIR)/test_%.c,%,$(VALGRIND_TEST_SRC))
VALGRIND_TEST_BINS := $(patsubst %,test/test_%,$(VALGRIND_TEST_NAMES))

# Pattern rule for building test binaries
test/test_%: $(TEST_DIR)/test_%.c $(SRC_DIR)/%.c src/stubs.c
	@echo "Building test for $*"
	@echo "Test source: $(TEST_DIR)/test_$*.c"
	@echo "Source file: $(SRC_DIR)/$*.c"
	@echo "Test CFLAGS: $(TEST_CFLAGS)"
	@echo "Test LDFLAGS: $(TEST_LDFLAGS)"
	@mkdir -p test
	$(CC) $(TEST_CFLAGS) -DTESTING -o $@ $^ -Isrc $(TEST_LDFLAGS)

# Main test target that builds and runs all tests
test: $(TEST_BINS)
	@for test in $(TEST_BINS); do \
		echo "\nRunning $$test..."; \
		./$$test; \
		if [ $$? -ne 0 ]; then \
			echo "$$test failed!"; \
			exit 1; \
		fi; \
	done
	@echo "\nAll tests passed!"

# Clean all build artifacts and test binaries
clean:
	rm -rf $(BUILD_DIR) $(TARGET) src/check*.c src/*.BAK src/*.NEW $(TEST_BINS)

.PHONY: all clean test

.DELETE_ON_ERROR:

# Include automatically generated dependency files (.d)
-include $(OBJ_FILES:.o=.d)

# Documentation with Doxygen
docs:
	doxygen

# Run with sanitizers
sanitize: CFLAGS += $(SANITIZER_FLAGS)
sanitize: all

# Memory check with valgrind for valgrind-specific test binaries only
memcheck: TEST_CFLAGS := $(CFLAGS)
memcheck: TEST_LDFLAGS := $(LDFLAGS) -lsodium -lcheck -lsubunit -pthread -lrt -lm
memcheck: $(VALGRIND_TEST_BINS)
	@for test in $(VALGRIND_TEST_BINS); do \
		echo "\nRunning valgrind on $$test..."; \
		valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1 --track-fds=yes --trace-children=yes ./$$test; \
	done

# Fuzzing targets
FUZZ_DIR = test/fuzz
FUZZ_BUILD_DIR = build/fuzz
FUZZ_CORPUS_DIR = test/fuzz/corpus
FUZZ_OUTPUT_DIR = test/fuzz/output

FUZZ_TARGETS = account login password
FUZZ_BINARIES = $(addprefix $(FUZZ_BUILD_DIR)/fuzz_, $(FUZZ_TARGETS))

# Fuzzing flags for building fuzz targets with libFuzzer
FUZZ_CC = clang
FUZZ_CFLAGS = -g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -std=c11 -pedantic-errors -Wall -Wextra -I$(SRC_DIR)

# Create corpus directories for each target
$(FUZZ_CORPUS_DIR)/%:
	mkdir -p $@

# Create output directories for each target
$(FUZZ_OUTPUT_DIR)/%:
	mkdir -p $@

# Rule to build fuzz targets
$(FUZZ_BUILD_DIR)/fuzz_%: $(FUZZ_DIR)/fuzz_%.c $(SRC_DIR)/%.c | $(FUZZ_BUILD_DIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^ $(LDFLAGS)

# Create the fuzz build directory
$(FUZZ_BUILD_DIR):
	mkdir -p $@

# Build all fuzzing targets
fuzz: install-dependencies $(FUZZ_BINARIES) $(foreach t, $(FUZZ_TARGETS), $(FUZZ_CORPUS_DIR)/$(t)) $(foreach t, $(FUZZ_TARGETS), $(FUZZ_OUTPUT_DIR)/$(t))
	@echo "Fuzzing targets built. Run 'make run-fuzz' to start fuzzing."

# Run a single fuzzer
run-fuzz-%: $(FUZZ_BUILD_DIR)/fuzz_% $(FUZZ_CORPUS_DIR)/% $(FUZZ_OUTPUT_DIR)/%
	$(FUZZ_BUILD_DIR)/fuzz_$* -max_total_time=$(FUZZ_TIME) $(FUZZ_CORPUS_DIR)/$* $(FUZZ_OUTPUT_DIR)/$*

# Run all fuzzers 
run-fuzz: fuzz
	@echo "Running all fuzzers for $(FUZZ_TIME) seconds each"
	@for target in $(FUZZ_TARGETS); do \
		echo "Fuzzing $$target..."; \
		$(FUZZ_BUILD_DIR)/fuzz_$$target -max_total_time=$(FUZZ_TIME) $(FUZZ_CORPUS_DIR)/$$target $(FUZZ_OUTPUT_DIR)/$$target; \
	done
	@echo "Fuzzing completed. Check output directories for results."

# Set default fuzzing time (in seconds) if not provided
FUZZ_TIME ?= 60