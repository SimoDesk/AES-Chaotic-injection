CC = gcc

MAP_FLAG ?=

CFLAGS = -O3 -Wall -Wextra $(MAP_FLAG)
PROFILING_FLAGS = -fstack-usage -fcallgraph-info -dumpdir $(AUX_DIR)

TARGET_DIR = benchmark
TARGET ?= $(TARGET_DIR)/benchmark_engine 

AES_PROF = $(if $(PROFILE_AES), $(PROFILING_FLAGS),)
CHAOS_PROF = $(if $(PROFILE_CHAOS), $(PROFILING_FLAGS),)

.PHONY: clean directories build

build: directories $(TARGET)

directories:
	mkdir -p $(TARGET_DIR)
	mkdir -p $(AUX_DIR)

$(TARGET): main.o tester.o aes.o aes_chaos.o
	$(CC) $(CFLAGS) $(MAP_FLAG) main.o tester.o aes.o aes_chaos.o -o $(TARGET) -lm

main.o: main.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c main.c -o main.o

tester.o: tester.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c tester.c -o tester.o

aes.o: ../aes_default/aes.c directories
	$(CC) $(CFLAGS) $(MAP_FLAG) $(AES_PROF) -c ../aes_default/aes.c -o aes.o

aes_chaos.o: ../aes_chaos/aes_chaos.c directories
	$(CC) $(CFLAGS) $(MAP_FLAG) $(CHAOS_PROF) -c ../aes_chaos/aes_chaos.c -o aes_chaos.o

clean:
	rm -f *.o $(TARGET_DIR)/benchmark_*