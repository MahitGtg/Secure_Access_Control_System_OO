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

# The target executable.
# This executable is created by linking together all object files
# obtained from a .c file in the `src` directory; so exactly one
# .c file should contain a `main` function.
# Alternative implementations of main can be wrapped in #ifdefs, as
# long as exactly one is compiled; then they can be selected by
# supplying `-D` flags to `make` and thence to the compiler.
# See e.g. `alternate_main.c`
TARGET = $(BIN_DIR)/app

SRC_FILES := $(shell find $(SRC_DIR) -name "*.c")

OBJ_FILES := $(SRC_FILES:.c=.o)
OBJ_FILES := $(subst $(SRC_DIR),$(BUILD_DIR),$(OBJ_FILES))

SRC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAGS := $(addprefix -I, $(SRC_DIRS))

# get compiler flags for installed libraries using pkg-config.
PKG_DEPS := $(shell cat libraries.txt | grep -v '^#' | xargs)

# Set PKG_CFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the compiler flags for the dependencies
PKG_CFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --cflags $(PKG_DEPS)))

# Set PKG_LDFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the linker flags for the dependencies
PKG_LDFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --libs $(PKG_DEPS)))

# You may wish to add additional compiler flags or linker flags here
# (e.g. to change the optimization level, enable sanitizers, etc.)
# This is helpful when testing your code locally, even though we will
# not necessarily use the same flags when testing your code.
DEBUG = -g -fno-omit-frame-pointer
CFLAGS = $(DEBUG) -std=c11 -pedantic-errors -Wall -Wextra $(INC_FLAGS) $(PKG_CFLAGS)
LDFLAGS = $(PKG_LDFLAGS)

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
	$(CC) $(CFLAGS) $(INC_FLAGS) -MMD -MP -c $< -o $@

# targets for each object file
$(foreach obj_file,$(OBJ_FILES),$(eval $(obj_file):))

# Install dependencies
install-dependencies:
	cat apt-packages.txt | sudo ./scripts/install-deps.sh

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all clean

.DELETE_ON_ERROR:

# Include automatically generated dependency files (.d)
-include $(OBJ_FILES:.o=.d)

