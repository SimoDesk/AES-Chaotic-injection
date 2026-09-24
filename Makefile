CC = gcc

# Compiler flags for optimization and memory usage analysis. -O3 enables high-level optimizations, -Wall and -Wextra enable all warnings for better code quality.
CFLAGS = -O3 -Wall -Wextra
PROFILING_FLAGS = -fstack-usage -fcallgraph-info -dumpdir $(AUX_DIR)

# Target executable name and auxiliary directory for storing profiling information
TARGET = banchmark
AUX_DIR = run_info/

.PHONY: all clean run

# Clean the previous build and compile the target executable
all: clean $(TARGET)

# Linking rule: combines the object files (.o) to create the executable
$(TARGET): main.o tester.o aes.o
	$(CC) $(CFLAGS) main.o tester.o aes.o -o $(TARGET)

# Standard compilation: creates intermediate objects without generating .su and .ci
main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o

tester.o: tester.c
	$(CC) $(CFLAGS) -c tester.c -o tester.o

# Profiled compilation: applies memory extraction only here
aes.o: aes_default/aes.c
	mkdir -p $(AUX_DIR)
	$(CC) $(CFLAGS) $(PROFILING_FLAGS) -c aes_default/aes.c -o aes.o

# Run the executable with sudo privileges if the 'run' target is invoked
run: all
	sudo ./$(TARGET)

# Install the necessary dependencies for the project, including NetworkX, Matplotlib, and pip for Python 3.
setup:
	sudo apt update
	sudo apt install -y python3-networkx python3-matplotlib python3-pip

# Clean up the build artifacts and auxiliary files
clean:
	rm -f $(TARGET) *.o
	rm -rf $(AUX_DIR)