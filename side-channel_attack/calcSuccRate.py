import subprocess

import csv

import time
import random

import os
import tempfile
import concurrent.futures

import attack as attack_module

# Number of tests to run for each map type to calculate the average success rate.
TEST_QUANTITY = 1000

# Path to the CSV file where the average success rates for each map type will be saved.
SUCCESS_RATES_CSV = "data/success_rates.csv"

# List of chaotic map types to be tested in the side-channel attack. Each map type will be used to generate different sets of training and attack data for the AES key recovery process.
MAPS = ["standard",'logistic','tent','henon','arnold','sine','chebyshev','lorenz','chen','rossler']

# Function to run a single test for a given chaotic map type and random seed. It generates training and attack data, 
# performs the first phase of the side-channel attack to recover the first 12 bytes of the AES key, and returns the success rate of the key recovery process.
def run_single_test(map_type, seed):   

    # Seed the random number generator 
    random.seed(seed)
    randVal = random.randint(0, 9999)

    # Create a temporary directory to store the training and attack data CSV files for this test. The directory will be automatically cleaned up after the test is completed.
    with tempfile.TemporaryDirectory() as temp_dir:

        # Set the paths for the training and attack CSV files in the temporary directory. These files will be used by the attack module to perform the key recovery process.
        attack_module.TRAINING_CSV = os.path.join(temp_dir, "training_data.csv")
        attack_module.ATTACK_CSV = os.path.join(temp_dir, "attack_data.csv")

        # Run the external command to generate the training and attack data for the specified chaotic map type and random seed.
        res = subprocess.run([f"./{attack_module.EXE_WD}create_ciphers", map_type, str(randVal), temp_dir], check=True, capture_output=True, text=True)

        # Set the real AES key in the attack module based on the output of the data generation command. The key is extracted from the command's stdout.
        for line in res.stdout.strip().splitlines():
            if line.startswith("KEY="):
                attack_module.REAL_KEY = line.split("=")[1].strip()
            elif len(line) == 64 and "=" not in line:
                attack_module.REAL_KEY = line.strip()

        # Perform the first phase of the side-channel attack using the generated training and attack data. The success rate of the key recovery process is returned.
        _, succRate = attack_module.phase_1_attack(collect_data=False)

    return succRate

if __name__ == "__main__":
    subprocess.run(["make", "clear"], check=True)
    
    subprocess.run(["make"], check=True)

    # Open the CSV file for writing the average success rates for each chaotic map type. The file will be created if it doesn't exist, and any existing content will be overwritten.
    with open(SUCCESS_RATES_CSV, "w", newline='') as csvfile:

        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Map", "Average Success Rate (%)"])

        # Iterate over each chaotic map type in the MAPS list to perform the tests and calculate the average success rate for each map type.
        for map in MAPS:

            # Seed the random number generator with the current time to ensure that each test run uses a different random seed, 
            # providing variability in the generated training and attack data.
            timeSeed = int(time.time())

            # avgRate will accumulate the success rates from each test
            avgRate = 0.0

            # counter will keep track of the number of completed tests for progress reporting
            counter = 0

            # Use a ProcessPoolExecutor to run multiple tests in parallel, improving the efficiency of the testing process. 
            # Each test is submitted as a separate task to the executor, and the results are collected as they complete.
            with concurrent.futures.ProcessPoolExecutor() as executor:
                futures = [executor.submit(run_single_test, map, timeSeed + i) for i in range(TEST_QUANTITY)]

                # As each test completes, the success rate is added to avgRate, and the counter is incremented. Progress is printed to the console in real-time.
                for future in concurrent.futures.as_completed(futures):
                    avgRate += future.result()
                    counter += 1
                    
                    print(f"\rProgress: {counter}/{TEST_QUANTITY} completed test with {map} map.", end='', flush=True)

            # After all tests for the current map type are completed, calculate the average success rate by dividing the accumulated success rates by the total number of tests
            # and print the result to the console. The average success rate is also written to the CSV file for record-keeping and further analysis.
            avgRate /= TEST_QUANTITY

            print(f" ===> Average success rate over {TEST_QUANTITY} tests: {avgRate:.2f}%\n")

            csv_writer.writerow([map, f"{avgRate:.2f}"])