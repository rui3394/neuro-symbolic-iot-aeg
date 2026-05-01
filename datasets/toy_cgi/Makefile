CC := gcc
BUILD_DIR := build
TARGETS := $(BUILD_DIR)/toy_01 $(BUILD_DIR)/toy_02 $(BUILD_DIR)/toy_03 $(BUILD_DIR)/toy_04 $(BUILD_DIR)/toy_05

ifeq ($(OS),Windows_NT)
	SHELL := cmd.exe
	.SHELLFLAGS := /C
	CFLAGS := -O0 -g -fno-pie -Wall -Wextra
	LDFLAGS :=
	MKDIR_BUILD := if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	RM_BUILD := if exist $(BUILD_DIR) rmdir /s /q $(BUILD_DIR)
	POST_BUILD = if exist $@.exe copy /Y $@.exe $@ > NUL || exit /b 0
else
	CFLAGS := -O0 -g -fno-pie -Wall -Wextra
	LDFLAGS := -no-pie
	MKDIR_BUILD := mkdir -p $(BUILD_DIR)
	RM_BUILD := rm -rf $(BUILD_DIR)
	POST_BUILD = true
endif

.PHONY: all clean

all: $(TARGETS)

$(BUILD_DIR)/toy_01: toy_01_basic_cmd.c
	$(MKDIR_BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	$(POST_BUILD)

$(BUILD_DIR)/toy_02: toy_02_filter_chars.c
	$(MKDIR_BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	$(POST_BUILD)

$(BUILD_DIR)/toy_03: toy_03_length_limit.c
	$(MKDIR_BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	$(POST_BUILD)

$(BUILD_DIR)/toy_04: toy_04_branch_check.c
	$(MKDIR_BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	$(POST_BUILD)

$(BUILD_DIR)/toy_05: toy_05_safe_case.c
	$(MKDIR_BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	$(POST_BUILD)

clean:
	$(RM_BUILD)
