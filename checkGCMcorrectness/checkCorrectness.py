import json
import os
import subprocess

ENC_TESTS_PATH = "tests/gcmEncryptExtIV256.rsp"
DEC_TESTS_PATH = "tests/gcmDecrypt256.rsp"

# Function to parse the CAVS test data files
def parse_cavs_data(file_path):
    # all_tests is a dictionary where the keys are tuples of parameter settings (Keylen, IVlen, PTlen, AADlen, Taglen) 
    # and the values are lists of test cases corresponding to those parameters.
    all_tests = {}

    # current_params is a dictionary that holds the current set of parameters being processed (Keylen, IVlen, PTlen, AADlen, Taglen).
    current_params = {}

    # current_test is a dictionary that holds the details of the current test case being processed.
    current_test = {}

    # newParams is a boolean flag that indicates whether a new set of parameters has been encountered in the file.
    newParams = False
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            
            # Skip empty lines and comments (lines starting with '#').
            if not line or line.startswith('#'):
                continue

            # Check for parameter lines and extract their values. When a new parameter line is found, set newParams to True to indicate that a new set of parameters is being processed.
            if line.startswith('[Keylen = '):
                keylen = int(line.split('=')[1].strip(' ]'))

                newParams = True

                continue

            # Check for other parameter lines and extract their values.
            if line.startswith('[IVlen = '):
                ivlen = int(line.split('=')[1].strip(' ]'))
                continue

            if line.startswith('[PTlen = '):
                ptlen = int(line.split('=')[1].strip(' ]'))
                continue

            if line.startswith('[AADlen = '):
                aadlen = int(line.split('=')[1].strip(' ]'))
                continue

            if line.startswith('[Taglen = '):
                taglen = int(line.split('=')[1].strip(' ]'))
                continue

                
            # Check for test case lines and extract their values. When a new test case is found, if there is an existing current_test,
            #  it is added to the list of tests for the current set of parameters in all_tests. 
            # Then, a new current_test dictionary is created to hold the details of the new test case.
            if line.startswith('Count = '):
                if current_test:
                    all_tests[tuple(current_params.items())].append(current_test)

                current_test = {'Count': int(line.split('=')[1].strip())}

            elif '=' in line:
                key, val = line.split('=', 1)
                current_test[key.strip()] = val.strip()

            elif line == 'FAIL':
                current_test['FAIL'] = True


            # When a new set of parameters is encountered, the current_params dictionary is updated with the new parameter values,
            # and an empty list is created in all_tests for the new set of parameters. The newParams flag is then reset to False.
            if newParams:
                current_params = {
                                'Keylen': keylen,
                                'IVlen': ivlen,
                                'PTlen': ptlen,
                                'AADlen': aadlen,
                                'Taglen': taglen
                            }

                all_tests.update({tuple(current_params.items()): []})
                newParams = False

        # After processing all lines in the file, if there is a current_test that has not been added to all_tests, it is added to the list of tests for the current set of parameters.
        all_tests[tuple(current_params.items())].append(current_test)
            
    return all_tests

if __name__ == "__main__":
    # First, build the C code using make    
    subprocess.run(["make", "build"], cwd=os.path.dirname(os.path.abspath(__file__)))

    # Then, run the tests and write the results to a file
    with open("results.txt", "w", encoding="utf-8") as file:

        # Starting with encryption tests
        file_enc_path = ENC_TESTS_PATH 
        encTests = parse_cavs_data(file_enc_path)

        file.write("Encryption tests:\n")

        for params, tests in encTests.items():
            # Convert lengths from bits to bytes for the C program
            keylen_b = params[0][1] // 8
            ivlen_b = params[1][1] // 8
            ptlen_b = params[2][1] // 8
            aadlen_b = params[3][1] // 8
            taglen_b = params[4][1] // 8

            file.write(f"Running tests with parameters: Keylen={keylen_b*8}, IVlen={ivlen_b*8}, PTlen={ptlen_b*8}, AADlen={aadlen_b*8}, Taglen={taglen_b*8}\n")

            # For each test, run the C program and capture its output
            for test in tests:
                result = subprocess.run(
                    ["./test_correctness", 
                    "e", 
                    str(keylen_b), str(ivlen_b), str(ptlen_b), str(aadlen_b), str(taglen_b), 
                    test.get('Key',''), test.get('IV',''), test.get('PT',''), test.get('AAD',''), test.get('CT',''), test.get('Tag','')],
                    capture_output=True, text=True
                )
                output = result.stdout.strip().lower()

                # Check if the output contains the expected ciphertext and tag
                if f"ciphertext: {test.get('CT','').lower()}" in output and f"tag: {test.get('Tag','').lower()}" in output:
                    file.write(f"ENC Test {test['Count']} PASS\n")
                else:
                    file.write(f"ENC Test {test['Count']} FAIL: Output error or program crash\n")


        # Now, run the decryption tests
        file.write("\nDecryption tests:\n")

        file_dec_path = DEC_TESTS_PATH
        decTests = parse_cavs_data(file_dec_path)

        for params, tests in decTests.items():
            # As before, convert lengths from bits to bytes for the C program
            keylen_b = params[0][1] // 8
            ivlen_b = params[1][1] // 8
            ptlen_b = params[2][1] // 8
            aadlen_b = params[3][1] // 8
            taglen_b = params[4][1] // 8

            file.write(f"Running tests with parameters: Keylen={keylen_b*8}, IVlen={ivlen_b*8}, PTlen={ptlen_b*8}, AADlen={aadlen_b*8}, Taglen={taglen_b*8}\n")

            # For each test, run the C program and capture its output
            for test in tests:
                result = subprocess.run(
                    ["./test_correctness", 
                    "d", 
                    str(keylen_b), str(ivlen_b), str(ptlen_b), str(aadlen_b), str(taglen_b), 
                    test.get('Key',''), test.get('IV',''),  test.get('PT',''), test.get('AAD',''), test.get('CT',''), test.get('Tag','')],
                    capture_output=True, text=True
                )
                
                output = result.stdout.strip().lower()
                expected_fail = test.get('FAIL', False)

                # Check if the output contains the expected plaintext or indicates a decryption failure
                if expected_fail and "decryption failed" in output:
                    file.write(f"DEC Test {test['Count']} PASS (Authentication failure correctly detected)\n")
                elif not expected_fail and "decryption successful" in output and test.get('PT','').lower() in output:
                    file.write(f"DEC Test {test['Count']} PASS (Correctly deciphered)\n")
                else:
                    file.write(f"DEC Test {test['Count']} FAIL: Unexpected behavior\n")

    
