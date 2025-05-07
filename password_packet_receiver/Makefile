CC = clang
CFLAGS = -Wall -g -O2
TARGET = packet_sender
BUILD_DIR = build
BIN_DIR = ../bin

all: $(BUILD_DIR)/$(TARGET) copy

$(BUILD_DIR)/$(TARGET): packet_recv.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

copy: $(BUILD_DIR)/$(TARGET) | $(BIN_DIR)
	cp $< $(BIN_DIR)/

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -rf $(BUILD_DIR)
