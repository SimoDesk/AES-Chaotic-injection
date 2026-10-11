import os
import subprocess
import sys

from memoryCalculator import calc_memory
from overHeadCalculator import calc_overhead

# Define the mapping of map names to their corresponding compilation flags
MAPS_CONFIG = {
    "standard": "-DNO_CHAOS",
    "logistic": "-DUSE_LOGISTIC_MAP",
    "tent": "-DUSE_TENT_MAP",
    "henon": "-DUSE_HENON_MAP",
    "arnold": "-DUSE_ARNOLD_CAT_MAP",
    "sine": "-DUSE_SINE_MAP",
    "chebyshev": "-DUSE_CHEBYSHEV_MAP",
    "lorenz": "-DUSE_LORENZ_MAP",
    "chen": "-DUSE_CHEN_MAP",
    "rossler": "-DUSE_ROSSLER_MAP"
}

def run_benchmarks():

    # Check if the script is run in time-only mode
    time_only_mode = "--time-only" in sys.argv
    
    # If the results.csv file exists, remove it to start fresh
    if os.path.exists("results.csv"):
        os.remove("results.csv")

    for map_name, base_macro in MAPS_CONFIG.items():

        # Create the auxiliary directory for the current map
        aux_dir = f"run_info/{map_name}/"

        # Name of the target executable for the current map
        target_exe = f"benchmark/benchmark_{map_name}"
        
        # If the test is run in time-only mode, append the TIME_ONLY flag to the macro
        macro = f"{base_macro} -DTIME_ONLY" if time_only_mode else base_macro
        
        # Set the profiler flag based on whether the map is standard or chaotic
        profiler = "PROFILE_AES=1" if map_name == "standard" else "PROFILE_CHAOS=1"

        # Build the command to compile the benchmark for the current map
        make_cmd = [
            "make", "-B", "build",
            f"MAP_FLAG={macro}",
            f"AUX_DIR={aux_dir}",
            f"TARGET={target_exe}",
            profiler
        ]
        subprocess.run(make_cmd, check=True)

        # Run the benchmark executable for the current map
        subprocess.run([target_exe], check=True)

    # Calculate memory usage and overhead after running all benchmarks
    calc_memory()
    calc_overhead()

if __name__ == "__main__":

    subprocess.run(["make", "clear"], check=True)

    run_benchmarks()
