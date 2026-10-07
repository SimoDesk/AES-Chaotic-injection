#include "../aes_default/aes.h"
#include "../aes_chaos/aes_chaos.h"

#define TEXT_LENGTH (1024 * 1024 * 2) // MB

#define AAD_LENGTH 128 // Length of the Additional Authenticated Data (AAD) in bytes

#define TEST_NUMBER 10 // Set to 1 for a single test, or any other number for multiple tests

#define FILENAME "results.csv" // File to save the results

// Structure to hold the results of AES-GCM encryption and decryption
struct stats {
    double average_time;
    double time_standard_deviation;
    double elapsed_time;
    uint64_t energy_consumed;
    double power_consumed;
};

// Function to create a random key based on a seed value. The key is filled with random bytes generated using the standard rand() function, which is seeded with the provided seed value. The size of the key is specified by the key_size parameter.
void getRandomValue(uint8_t* key, size_t key_size);

// Function to benchmark the AES-GCM encryption and decryption functions. The function takes the algorithm name,
// the plaintext, key, IV, and AAD as parameters. It performs multiple iterations of encryption and decryption, measuring the time and energy consumed for each operation.
void benchmark(struct stats* chypherStats, struct stats* decypherStats, const char* alg_name, uint8_t* text, uint8_t* key, uint8_t* iv, uint8_t* aad, ChaosMap chaos_map);