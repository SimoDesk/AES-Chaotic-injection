#include "aes_default/aes.h"
#include "aes_chaos/aes_chaos.h"

#define TEXT_LENGTH (1024 * 1024 * 5) // 5 MB

#define AAD_LENGTH 128 // Length of the Additional Authenticated Data (AAD) in bytes

#define TEST_NUMBER 2 // Set to 1 for a single test, or any other number for multiple tests

#define FILENAME "results.csv" // File to save the results

// Structure to hold the results of AES-GCM encryption and decryption
struct stats {
    double elapsed_time;
    uint64_t energy_consumed;
    double power_consumed;
};

// Function to create a random key based on a seed value. The key is filled with random bytes generated using the standard rand() function, which is seeded with the provided seed value. The size of the key is specified by the key_size parameter.
void getRandomValue(uint8_t* key, size_t key_size);

// Function to read the energy consumption from the specified file and return it as a uint64_t value. The function opens the file located at "/sys/class/powercap/intel_rapl/intel_rapl:0/energy_uj", reads the energy value, and returns it. If the file cannot be opened, the function returns 0.
uint64_t read_energy();

// Function to calculate and print the elapsed time, energy consumed, and power consumed during encryption and authentication. The function takes the start and end times as struct timespec, as well as the energy consumption values before and after the operation. It calculates the elapsed time in seconds, the energy consumed in microjoules, and the power consumed in watts, and prints these values to the console.
void calcStats(struct stats* st, struct timespec start, struct timespec end, uint64_t energy_start, uint64_t energy_end);

// Function to save the calculated statistics to a file.
void saveStatsToFile(struct stats* stEnc, struct stats* stDec, char* filename, const char* alg_name);

// Function to benchmark the AES-GCM encryption and decryption functions. The function takes the algorithm name,
// the plaintext, key, IV, and AAD as parameters. It performs multiple iterations of encryption and decryption, measuring the time and energy consumed for each operation.
void benchmark(struct stats* chypherStats, struct stats* decypherStats, const char* alg_name, uint8_t* text, uint8_t* key, uint8_t* iv, uint8_t* aad);

void benchmark_chaos(struct stats* chypherStats, struct stats* decypherStats, const char* map_name, uint8_t* text, uint8_t* key, uint8_t* iv, uint8_t* aad, ChaosMap chaos_map);