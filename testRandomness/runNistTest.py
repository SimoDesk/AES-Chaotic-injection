import os
import sys
import subprocess
import csv
import tempfile
import concurrent.futures

from createReport import create_report 

# First , determine the current directory and the root directory of the project
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(current_dir, ".."))
nist_suite_path = os.path.join(root_dir, "nist_suite")

# Add the NIST suite path to sys.path to allow importing modules from that directory
sys.path.append(nist_suite_path)

# Import the necessary modules from the NIST suite
from Tools import Tools
from FrequencyTest import FrequencyTest as ft
from RunTest import RunTest as rt
from Matrix import Matrix as mt
from Spectral import SpectralTest as st
from TemplateMatching import TemplateMatching as tm
from Universal import Universal as ut
from Complexity import ComplexityTest as ct
from Serial import Serial as serial
from ApproximateEntropy import ApproximateEntropy as aet
from CumulativeSum import CumulativeSums as cst
from RandomExcursions import RandomExcursions as ret

# Define the test types and corresponding functions to be printed in the CSV file
test_type = [
    '01. Frequency Test (Monobit)', 
    '02. Frequency Test within a Block', 
    '03. Run Test',
    '04. Longest Run of Ones in a Block', 
    '05. Binary Matrix Rank Test',
    '06. Discrete Fourier Transform (Spectral) Test',
    '07. Non-Overlapping Template Matching Test',
    '08. Overlapping Template Matching Test', 
    '09. Maurer\'s Universal Statistical test',
    '10. Linear Complexity Test',
    '11. Serial test', 
    '12. Approximate Entropy Test',
    '13. Cumulative Sums (Forward) Test', 
    '14. Cumulative Sums (Reverse) Test',
    '15. Random Excursions Test', 
    '16. Random Excursions Variant Test'
]

# Define a mapping of test indices to their corresponding functions
test_function = {
    0:ft.monobit_test, 1:ft.block_frequency, 2:rt.run_test, 3:rt.longest_one_block_test,
    4:mt.binary_matrix_rank_text, 5:st.spectral_test, 6:tm.non_overlapping_test,
    7:tm.overlapping_patterns, 8:ut.statistical_test, 9:ct.linear_complexity_test,
    10:serial.serial_test, 11:aet.approximate_entropy_test, 12:cst.cumulative_sums_test,
    13:cst.cumulative_sums_test, 14:ret.random_excursions_test, 15:ret.variant_test
}

# Define a function to run a single test, which will be executed in parallel
def run_single_test(args):

    # Unpack the arguments
    i, bin_filename = args

    # Get the name of the test based on the index
    nome_test = test_type[i]

    # Run the test and handle any exceptions that may occur
    try:
        # Read the binary file containing the ciphertext
        with open(bin_filename, 'rb') as f:
            raw_bytes = f.read()
            
        # Convert the raw bytes to a binary string representation
        binary_string = Tools.bytes_to_binary(raw_bytes)
        
        # Limit the binary string to a maximum of 1,000,000 bits for testing as per NIST recommendations
        max_bits = 1000000
        if len(binary_string) > max_bits:
            binary_string = binary_string[:max_bits]

        # Run the appropriate test function based on the index, if the test is the Cumulative Sums Test (index 13), run it in mode 1 (forward), otherwise run it normally
        if i == 13:
            res = test_function[i](binary_string, mode=1)
        else:
            res = test_function[i](binary_string)

        # Return the index, test name, and result
        return i, nome_test, res

    except Exception as e:
        return i, nome_test, f"Errore: {e}"

# Define the list of maps to be tested and the output CSV file path
MAPPE = ["standard",'logistic','tent','henon','arnold','sine','chebyshev','lorenz','chen','rossler']
OUTPUT_CSV = os.path.join(current_dir, "nist_results.csv")

N_TESTS = 55

# Define the main function to run the automation of tests
def run_automation():

    # Determine if a RAM-based temporary directory is available for improved performance, otherwise use the default temporary directory
    ram_based_dir = "/dev/shm" if os.path.exists("/dev/shm") else None

    # Create or overwrite the output CSV file and write the header row
    with open(OUTPUT_CSV, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Mappa", "Seed", "Test", "Risultato (P-Value, Status)"])

        # Use a temporary directory in RAM to store the generated ciphertexts and run the tests in order
        # to ensure that the tests are run in a clean environment and to improve performance by avoiding disk I/O
        with tempfile.TemporaryDirectory(dir=ram_based_dir) as temp_dir:

            # For each map in the list of maps, generate the ciphertext and run the NIST tests in parallel
            for mappa in MAPPE:

                map_output_dir = os.path.join(temp_dir, "ciphers", mappa)
                os.makedirs(map_output_dir, exist_ok=True)

                # For each seed from 0 to 99, run the extract_bin executable to generate ciphertexts with different seeds, ensuring that the tests are run on a variety of inputs
                # This follow the NIST recommendation to test the randomness of outputs across different keys and initial conditions, which is crucial for evaluating the security and robustness of the chaotic maps used in the AES encryption process
                for seed in range(0, 0 + N_TESTS):
                    subprocess.run(["./extract_bin", mappa, str(seed)], cwd=current_dir, check=True)

                    bin_filename = os.path.join(map_output_dir, f"cipher_{seed}.bin")

                    # Prepare the list of arguments for parallel execution, where each argument is a tuple of the test index and the binary filename
                    args_list = [(i, bin_filename) for i in range(len(test_function))]

                    # Initialize a dictionary to store the results of the tests
                    results = {}

                    # Use a ProcessPoolExecutor to run the tests in parallel, submitting each test to the executor and collecting the results as they complete
                    print(f"[{mappa.upper()} - {seed}] Test NIST avviati in parallelo...")

                    with concurrent.futures.ProcessPoolExecutor() as executor:
                        # Submit the tests to the executor and store the futures in a dictionary, mapping each future to its corresponding argument 
                        # in a dictionary comprehension, allowing us to track which test corresponds to which future as they complete
                        futures = {executor.submit(run_single_test, arg): arg for arg in args_list}

                        # As each future completes, retrieve the result and print the completion message, storing the results in the results dictionary
                        for future in concurrent.futures.as_completed(futures):
                            i, nome_test, risultato = future.result()
                            print(f"  [COMPLETATO] -> {nome_test}")
                            results[i] = (nome_test, risultato)
                    
                    # After all tests for the current map and seed are completed, write the results to the CSV file
                    for i in range(len(test_function)):
                        nome, res = results[i]
                        writer.writerow([mappa, seed, nome, str(res)])

                    # Clean up the generated binary file after testing
                    if os.path.exists(bin_filename):
                        os.remove(bin_filename)  
if __name__ == "__main__":

    subprocess.run(["make", "clear"], cwd=current_dir, check=True)
    subprocess.run(["make", "build"], cwd=current_dir, check=True)

    run_automation()

    create_report(OUTPUT_CSV)