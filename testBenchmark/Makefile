CC = gcc

# Map_flag is set externally to control the inclusion of map files during compilation.
MAP_FLAG ?=

# Compiler flags for optimization and warnings. -O3 enables high-level optimizations, -Wall and -Wextra enable all warnings for better code quality.
CFLAGS = -O3 -Wall -Wextra $(MAP_FLAG)

# Profiling flags for stack usage and call graph information.
PROFILING_FLAGS = -fstack-usage -fcallgraph-info -dumpdir $(AUX_DIR)

# Auxiliary directory for storing profiling data and other temporary files.
TARGET_DIR = benchmark
AUX_DIR = run_info
TARGET ?= $(TARGET_DIR)/benchmark_engine 

# If the PROFILE_AES or PROFILE_CHAOS variables are set, the corresponding profiling flags will be included during compilation.
AES_PROF = $(if $(PROFILE_AES), $(PROFILING_FLAGS),)
CHAOS_PROF = $(if $(PROFILE_CHAOS), $(PROFILING_FLAGS),)

.PHONY: clear directories build setup

build: directories $(TARGET)

directories:
	mkdir -p $(TARGET_DIR)
	mkdir -p $(AUX_DIR)

$(TARGET): main.o tester.o aes.o aes_chaos.o
	$(CC) $(CFLAGS) $(MAP_FLAG) main.o tester.o aes.o aes_chaos.o -o $(TARGET) -lcrypto -lm

main.o: main.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c main.c -o main.o

tester.o: tester.c
	$(CC) $(CFLAGS) $(MAP_FLAG) -c tester.c -o tester.o

aes.o: ../aes_default/aes.c directories
	$(CC) $(CFLAGS) $(MAP_FLAG) $(AES_PROF) -c ../aes_default/aes.c -o aes.o

aes_chaos.o: ../aes_chaos/aes_chaos.c directories
	$(CC) $(CFLAGS) $(MAP_FLAG) $(CHAOS_PROF) -c ../aes_chaos/aes_chaos.c -o aes_chaos.o

clear:
	rm -f *.o $(TARGET_DIR)/benchmark_*
	rm -f plots/*.png
	rm -rf $(AUX_DIR)


# Let the user know that they can run 'make setup' to install the required Python packages for graph generation and analysis.
setup:
	sudo apt update
	sudo apt-get install libssl-dev
	sudo apt install -y python3-networkx python3-matplotlib python3-pip graphviz python3-pygraphviz python3-pandas python3-seaborn