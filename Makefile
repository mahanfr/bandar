CC = gcc
CFLAGS = -Wall -Wextra
LIBS =
PROJECT_DIR := .
SRC_DIR = $(PROJECT_DIR)/src
PROGRAM_ENTRY = $(SRC_DIR)/main.c
BUILD_DIR := $(PROJECT_DIR)/build
TARGET_NAME := bandar
TARGET = $(BUILD_DIR)/$(TARGET_NAME)

rwildcard = $(foreach d,$(wildcard $(1:=/*)),$(call rwildcard,$d,$2) $(filter $(subst *,%,$2),$d))
SRC = $(call rwildcard,$(SRC_DIR),*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC))

.PHONY: bandar clean

bandar: always $(TARGET)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@ echo CC $^
	$(CC) $(CFLAGS) -c $^ -o $@ $(CLIBS)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)
	@ echo DONE. CREATED $@

always:
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
