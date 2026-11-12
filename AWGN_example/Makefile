CC ?= gcc
CFLAGS ?= -O3
CFLAGS += -std=gnu11 -Wall -Wextra -Wpedantic
LDFLAGS += -lcrypto -lm

TARGET = testAWGN
MAP ?= none

.PHONY: all build run clean clear

all: build

build: $(TARGET)

$(TARGET): testAWGN.c ../aes_default/aes.c ../aes_chaos/aes_chaos.c
	$(CC) $(CFLAGS) testAWGN.c ../aes_default/aes.c ../aes_chaos/aes_chaos.c \
		-o $@ $(LDFLAGS)

run: $(TARGET)
	./$(TARGET) $(MAP)

clean:
	rm -f $(TARGET)

clear: clean
