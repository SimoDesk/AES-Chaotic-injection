CC = gcc

# Compiler flags for optimization and warnings. -O3 enables high-level optimizations, -Wall and -Wextra enable all warnings for better code quality.
CFLAGS = -O3 -Wall -Wextra

# Additional flags for linking with jemalloc and enabling OpenMP support for parallel processing.
EXTRA_FLAGS = -ljemalloc -fopenmp

# Directory for storing the compiled executables.
TARGET_DIR = executables

.PHONY: all clear build build_bruteForce build_quickCheck setup

all: build build_bruteForce build_quickCheck

build: aes.o aes_chaos.o
	$(CC) $(CFLAGS) createCipher.c ../testBenchmark/tester.c ../aes_default/aes.c ../aes_chaos/aes_chaos.c -o $(TARGET_DIR)/create_ciphers -lcrypto -lm

build_bruteForce: aes.o aes_chaos.o
	$(CC) $(CFLAGS) $(EXTRA_FLAGS) bruteForcePhase.c ../testBenchmark/tester.c ../aes_default/aes.c ../aes_chaos/aes_chaos.c -o $(TARGET_DIR)/brute_force -lcrypto -lm

build_quickCheck: aes.o aes_chaos.o
	$(CC) $(CFLAGS) $(EXTRA_FLAGS) quickKeyCheck.c ../testBenchmark/tester.c ../aes_default/aes.c ../aes_chaos/aes_chaos.c -o $(TARGET_DIR)/quick_check -lcrypto -lm

aes.o: ../aes_default/aes.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c ../aes_default/aes.c -o aes.o

aes_chaos.o: ../aes_chaos/aes_chaos.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c ../aes_chaos/aes_chaos.c -o aes_chaos.o

clear:
	rm -f *.o $(TARGET_DIR)/benchmark_*
	rm -f create_ciphers
	rm -f brute_force
	rm -f *.csv
	rm -f plots/*.png

setup:
	sudo apt update
	sudo apt install python3-sklearn python3-pandas libjemalloc-dev
