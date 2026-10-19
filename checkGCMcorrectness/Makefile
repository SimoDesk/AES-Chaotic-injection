CC = gcc

# Compiler flags for optimization and warnings. -O3 enables high-level optimizations, -Wall and -Wextra enable all warnings for better code quality.
CFLAGS = -O3 -Wall -Wextra


.PHONY: all build

all: build

build: aes.o aes_chaos.o
	$(CC) $(CFLAGS) useAes.c ../testBenchmark/tester.c ../aes_default/aes.c ../aes_chaos/aes_chaos.c -o test_correctness -lcrypto -lm

aes.o: ../aes_default/aes.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c ../aes_default/aes.c -o aes.o

aes_chaos.o: ../aes_chaos/aes_chaos.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c ../aes_chaos/aes_chaos.c -o aes_chaos.o
