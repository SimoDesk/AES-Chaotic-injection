CC = gcc

# Compiler flags for optimization and warnings. -O3 enables high-level optimizations, -Wall and -Wextra enable all warnings for better code quality.
CFLAGS = -O3 -Wall -Wextra

# Generating a binary executable for testing purposes. This target compiles the testRandomness.c, tester.c, and AES implementation files into an executable named 'extract_bin' and runs it.
MAP ?= none

.PHONY: all clear build

all: build

build: 
	$(CC) $(CFLAGS) testRandomness.c ../testBenchmark/tester.c ../aes_default/aes.c ../aes_chaos/aes_chaos.c -o extract_bin -lm

clear:
	rm -f extract_bin
	rm -f cipher/*.bin
