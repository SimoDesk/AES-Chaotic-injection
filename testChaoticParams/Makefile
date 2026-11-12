CC = gcc

# Compiler flags for optimization and warnings. -O3 enables high-level optimizations, -Wall and -Wextra enable all warnings for better code quality.
CFLAGS = -O3 -Wall -Wextra

# Generating a binary executable for testing purposes. This target compiles the testRandomness.c, tester.c, and AES implementation files into an executable named 'extract_bin' and runs it.
MAP ?= none

.PHONY: all clean clear build

all: build

build: aes.o aes_chaos.o measure_stability
	$(CC) $(CFLAGS) ../testAvalancheEffect_KeySensitivity/createCipher.c ../testBenchmark/tester.c ../aes_default/aes.c ../aes_chaos/aes_chaos.c -o test_params -lcrypto -lm

measure_stability: measure_stability.c ../aes_chaos/aes_chaos.c ../aes_chaos/aes_chaos.h
	$(CC) $(CFLAGS) measure_stability.c ../aes_chaos/aes_chaos.c -o $@ -lcrypto -lm

aes.o: ../aes_default/aes.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c ../aes_default/aes.c -o aes.o

aes_chaos.o: ../aes_chaos/aes_chaos.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c ../aes_chaos/aes_chaos.c -o aes_chaos.o

clear:
	rm -f test_params
	rm -f measure_stability
	rm -f *.csv
	find ciphers -type f -delete 2>/dev/null || true
	find plots -type f -delete 2>/dev/null || true

clean:
	$(MAKE) clear
