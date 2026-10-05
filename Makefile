CC = gcc

# Compiler flags for optimization and warnings. -O3 enables high-level optimizations, -Wall and -Wextra enable all warnings for better code quality.
CFLAGS = -O3 -Wall -Wextra $(MAP_FLAG)
# Profiling flags for generating stack usage and call graph information. These flags are used when profiling is enabled for specific components.
PROFILING_FLAGS = -fstack-usage -fcallgraph-info -dumpdir $(AUX_DIR)

# Directories for the benchmark executable and auxiliary files. 
# The benchmark executable will be placed in the 'benchmark' directory, and auxiliary files (like profiling data) will be stored in the 'run_info' directory.
TARGET_DIR = benchmark
BASE_AUX_DIR = run_info

# Default target and auxiliary directory for the benchmark. The TARGET variable specifies the path to the benchmark executable, 
# and AUX_DIR specifies where auxiliary files will be stored.
TARGET = $(TARGET_DIR)/benchmark_default
AUX_DIR = $(BASE_AUX_DIR)/default/

# Output file for storing results. The results of the benchmark will be written to 'results.txt'.
DATA_DESTINATION = results.csv

# Conditional compilation flags for selecting the chaotic map to be used in the AES implementation.
MAP_FLAG =

# Conditional flags for enabling profiling for AES and chaotic map implementations.
# If PROFILE_AES is set, profiling flags will be added for the AES implementation.
# If PROFILE_CHAOS is set, profiling flags will be added for the chaotic map implementation.
AES_PROF = $(if $(PROFILE_AES), $(PROFILING_FLAGS),)
CHAOS_PROF = $(if $(PROFILE_CHAOS), $(PROFILING_FLAGS),)

.PHONY: clean clean_objs all run run_standard run_logistic run_tent setup build_and_run_sudo directories

# Create necessary directories for the benchmark executable and auxiliary files.
directories:
	mkdir -p $(TARGET_DIR)
	mkdir -p $(AUX_DIR)

# Default target to build the benchmark executable. Cleans up any existing object files, creates necessary directories, and compiles the final executable.
all: clean_objs directories $(TARGET)

# Linking the object files to create the final benchmark executable
$(TARGET): main.o tester.o aes.o aes_chaos.o
	$(CC) $(CFLAGS) main.o tester.o aes.o aes_chaos.o -o $(TARGET) -lm

# Compiling source files into object files
main.o: main.c
	$(CC) $(CFLAGS) -c main.c -o main.o
tester.o: tester.c
	$(CC) $(CFLAGS) -c tester.c -o tester.o

# Compiling AES source files into object files with exclusive profiling flags for AES implementation
aes.o: aes_default/aes.c directories
	$(CC) $(CFLAGS) $(AES_PROF) -c aes_default/aes.c -o aes.o

# Compiling AES with chaotic map source files into object files with exclusive profiling flags for chaotic map implementation
aes_chaos.o: aes_chaos/aes_chaos.c directories
	$(CC) $(CFLAGS) $(CHAOS_PROF) -c aes_chaos/aes_chaos.c -o aes_chaos.o

# Benchmarking targets with sudo privileges to mesure energy consumption ==========================================================================================

# Running the benchmark executable with sudo privileges. This target depends on the 'all' target to ensure that the executable is built before running.
build_and_run_sudo: all
	sudo ./$(TARGET)

# Running the benchmark with the standard AES implementation (no chaotic map). This target sets the appropriate MAP_FLAG and auxiliary directory for the standard implementation.
run_standard_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DNO_CHAOS" TARGET="$(TARGET_DIR)/benchmark_standard" AUX_DIR="$(BASE_AUX_DIR)/standard/" PROFILE_AES=1

# Running the benchmark with the logistic map implementation. This target sets the appropriate MAP_FLAG and auxiliary directory for the logistic map implementation.
run_logistic_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DUSE_LOGISTIC_MAP" TARGET="$(TARGET_DIR)/benchmark_logistic" AUX_DIR="$(BASE_AUX_DIR)/logistic/" PROFILE_CHAOS=1

# Running the benchmark with the tent map implementation. This target sets the appropriate MAP_FLAG and auxiliary directory for the tent map implementation.
run_tent_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DUSE_TENT_MAP" TARGET="$(TARGET_DIR)/benchmark_tent" AUX_DIR="$(BASE_AUX_DIR)/tent/" PROFILE_CHAOS=1

# Running the benchmark with the Henon map implementation. This target sets the appropriate MAP_FLAG and auxiliary directory for the Henon map implementation.
run_henon_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DUSE_HENON_MAP" TARGET="$(TARGET_DIR)/benchmark_henon" AUX_DIR="$(BASE_AUX_DIR)/henon/" PROFILE_CHAOS=1

# Running the benchmark with the Arnold Cat map implementation. This target sets the appropriate MAP_FLAG and auxiliary directory for the Arnold Cat map implementation.
run_arnold_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DUSE_ARNOLD_CAT_MAP" TARGET="$(TARGET_DIR)/benchmark_arnold" AUX_DIR="$(BASE_AUX_DIR)/arnold/" PROFILE_CHAOS=1

# Running the benchmark with the Sine map implementation. This target sets the appropriate MAP_FLAG and auxiliary directory for the Sine map implementation.
run_sine_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DUSE_SINE_MAP" TARGET="$(TARGET_DIR)/benchmark_sine" AUX_DIR="$(BASE_AUX_DIR)/sine/" PROFILE_CHAOS=1

# Running the benchmark with the Lorenz map implementation. This target sets the appropriate MAP_FLAG and auxiliary directory for the Lorenz map implementation.
run_lorenz_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DUSE_LORENZ_MAP" TARGET="$(TARGET_DIR)/benchmark_lorenz" AUX_DIR="$(BASE_AUX_DIR)/lorenz/" PROFILE_CHAOS=1

# Running the benchmark with the Chen map implementation. This target sets the appropriate MAP_FLAG and auxiliary directory for the Chen map implementation.
run_chen_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DUSE_CHEN_MAP" TARGET="$(TARGET_DIR)/benchmark_chen" AUX_DIR="$(BASE_AUX_DIR)/chen/" PROFILE_CHAOS=1

# Running the benchmark with the Rossler map implementation. This target sets the appropriate MAP_FLAG and auxiliary directory for the Rossler map implementation.
run_rossler_sudo:
	$(MAKE) build_and_run_sudo MAP_FLAG="-DUSE_ROSSLER_MAP" TARGET="$(TARGET_DIR)/benchmark_rossler" AUX_DIR="$(BASE_AUX_DIR)/rossler/" PROFILE_CHAOS=1

# =====================================================================================================================================================================


# Benchmarking targets without sudo privileges to mesure only time ====================================================================================================


# Running the benchmark executable without sudo privileges. This target depends on the 'all' target to ensure that the executable is built before running.
build_and_run: all
	 ./$(TARGET)

# Running the benchmark with the standard AES implementation (no chaotic map) without sudo privileges, doing so, only time is measured.
run_standard:
	$(MAKE) build_and_run MAP_FLAG="-DNO_CHAOS -DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_standard" AUX_DIR="$(BASE_AUX_DIR)/standard/" PROFILE_AES=1

# Running the benchmark with the logistic map implementation without sudo privileges, doing so, only time is measured.
run_logistic:
	$(MAKE) build_and_run MAP_FLAG="-DUSE_LOGISTIC_MAP-DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_logistic" AUX_DIR="$(BASE_AUX_DIR)/logistic/" PROFILE_CHAOS=1

# Running the benchmark with the tent map implementation without sudo privileges, doing so, only time is measured.
run_tent:
	$(MAKE) build_and_run MAP_FLAG="-DUSE_TENT_MAP-DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_tent" AUX_DIR="$(BASE_AUX_DIR)/tent/" PROFILE_CHAOS=1

# Running the benchmark with the Henon map implementation without sudo privileges, doing so, only time is measured.
run_henon:
	$(MAKE) build_and_run MAP_FLAG="-DUSE_HENON_MAP-DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_henon" AUX_DIR="$(BASE_AUX_DIR)/henon/" PROFILE_CHAOS=1

# Running the benchmark with the Arnold Cat map implementation without sudo privileges, doing so, only time is measured.
run_arnold:
	$(MAKE) build_and_run MAP_FLAG="-DUSE_ARNOLD_CAT_MAP-DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_arnold" AUX_DIR="$(BASE_AUX_DIR)/arnold/" PROFILE_CHAOS=1

# Running the benchmark with the Sine map implementation without sudo privileges, doing so, only time is measured.
run_sine:
	$(MAKE) build_and_run MAP_FLAG="-DUSE_SINE_MAP-DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_sine" AUX_DIR="$(BASE_AUX_DIR)/sine/" PROFILE_CHAOS=1

# Running the benchmark with the Lorenz map implementation without sudo privileges, doing so, only time is measured.
run_lorenz:
	$(MAKE) build_and_run MAP_FLAG="-DUSE_LORENZ_MAP-DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_lorenz" AUX_DIR="$(BASE_AUX_DIR)/lorenz/" PROFILE_CHAOS=1

# Running the benchmark with the Chen map implementation without sudo privileges, doing so, only time is measured.
run_chen:
	$(MAKE) build_and_run MAP_FLAG="-DUSE_CHEN_MAP-DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_chen" AUX_DIR="$(BASE_AUX_DIR)/chen/" PROFILE_CHAOS=1

# Running the benchmark with the Rossler map implementation without sudo privileges, doing so, only time is measured.
run_rossler:
	$(MAKE) build_and_run MAP_FLAG="-DUSE_ROSSLER_MAP-DTIME_ONLY" TARGET="$(TARGET_DIR)/benchmark_rossler" AUX_DIR="$(BASE_AUX_DIR)/rossler/" PROFILE_CHAOS=1

# =====================================================================================================================================================================


# Running all benchmarks and then executing the memory calculator script.
# This target ensures that all benchmarks are run sequentially and the results are processed.
run: clean run_standard_sudo run_logistic_sudo run_tent_sudo run_henon_sudo run_arnold_sudo run_sine_sudo run_lorenz_sudo run_chen_sudo run_rossler_sudo
	sudo chown $(USER):$(USER) $(DATA_DESTINATION)
	python3 memoryCalculator.py
	python3 overHeadCalculator.py

# Running all benchmarks without sudo privileges and then executing the memory calculator script.
# This target ensures that all benchmarks are run sequentially and the results are processed.
run_time_only: clean run_standard run_logistic run_tent run_henon run_arnold run_sine run_lorenz run_chen run_rossler
	sudo chown $(USER):$(USER) $(DATA_DESTINATION)
	python3 memoryCalculator.py
	python3 overHeadCalculator.py

# Install the necessary dependencies for the project, including NetworkX, Matplotlib, and pip for Python 3.
setup:
	sudo apt update
	sudo apt install -y python3-networkx python3-matplotlib python3-pip graphviz python3-pygraphviz python3-pandas

# Cleaning up object files generated during compilation. This target removes all .o files to ensure a clean build environment.
clean_objs:
	rm -f *.o

# Cleaning up generated results and auxiliary directories. This target removes result files and any auxiliary directories created during the benchmark runs.
clean:
	rm -f results*.csv *.o
	rm -rf $(BASE_AUX_DIR)/
	rm -rf $(TARGET_DIR)/