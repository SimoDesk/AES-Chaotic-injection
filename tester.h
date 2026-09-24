#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "aes_default/aes.h"

#define TEXT_LENGTH (1024 * 1024 * 5) // 5 MB

#define AAD_LENGTH 128 // Length of the Additional Authenticated Data (AAD) in bytes

#define TEST_NUMBER 100 // Set to 1 for a single test, or any other number for multiple tests

// Structure to hold the results of AES-GCM encryption and decryption
struct stats {
    double elapsed_time;
    uint64_t energy_consumed;
    double power_consumed;
};

// Function pointer types for AES-GCM encryption and decryption functions
typedef void (*AES_GCM_encrypt_func)(struct AES_ctx* ctx, struct AES_GCM_result* res, size_t length, size_t iv_len, uint8_t* aad, size_t aad_length);

// Function pointer type for AES-GCM decryption function. The function returns an integer indicating the success or failure of the decryption and authentication process.
typedef int (*AES_GCM_decrypt_func)(struct AES_ctx* ctx, struct AES_GCM_result* res, const uint8_t* tag, size_t length, size_t iv_len, uint8_t* aad, size_t aad_length);

// Function to create a random key based on a seed value. The key is filled with random bytes generated using the standard rand() function, which is seeded with the provided seed value. The size of the key is specified by the key_size parameter.
void getRandomValue(uint8_t* key, size_t key_size);

// Function to read the energy consumption from the specified file and return it as a uint64_t value. The function opens the file located at "/sys/class/powercap/intel_rapl/intel_rapl:0/energy_uj", reads the energy value, and returns it. If the file cannot be opened, the function returns 0.
uint64_t read_energy();

// Function to calculate and print the elapsed time, energy consumed, and power consumed during encryption and authentication. The function takes the start and end times as struct timespec, as well as the energy consumption values before and after the operation. It calculates the elapsed time in seconds, the energy consumed in microjoules, and the power consumed in watts, and prints these values to the console.
void calcStats(struct stats* st, struct timespec start, struct timespec end, uint64_t energy_start, uint64_t energy_end);

// Function to save the calculated statistics to a file.
void saveStatsToFile(struct stats* stEnc, struct stats* stDec, const char* filename, const char* alg_name);

// Function to benchmark the AES-GCM encryption and decryption functions. The function takes the algorithm name, pointers to the encryption and decryption functions, 
//the plaintext, key, IV, and AAD as parameters. It performs multiple iterations of encryption and decryption, measuring the time and energy consumed for each operation.
void banchmark(struct stats* chypherStats, struct stats* decypherStats, const char* alg_name, AES_GCM_encrypt_func encrypt_func, AES_GCM_decrypt_func decrypt_func, uint8_t* text, uint8_t* key, uint8_t* iv, uint8_t* aad);