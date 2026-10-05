#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "tester.h"

// Fill the buffer with random values
void getRandomValue(uint8_t* buf, size_t buf_size) {
    for (size_t i = 0; i < buf_size; i++) {
        buf[i] = (uint8_t)(rand() % 256);
    }
}

// Read the maximum energy range from the specified file and return it as a uint64_t value
uint64_t read_max_energy() {
    FILE *f = fopen("/sys/class/powercap/intel-rapl:0/max_energy_range_uj", "r");
    if (!f) return 262143328; // Fallback hardware
    
    uint64_t max_energy;
    if (fscanf(f, "%lu", &max_energy) != 1) {
        fclose(f);
        return 262143328;
    }
    fclose(f);
    return max_energy;
}

// Read the energy consumption from the specified file and return it as a uint64_t value
uint64_t read_energy() {

    #ifdef TIME_ONLY
        return 0; // Return 0 if TIME_ONLY is defined, as energy measurement is not needed
    #endif

    FILE *f = fopen("/sys/class/powercap/intel-rapl:0/energy_uj", "r");
    if (!f) return -1; // Return -1 if the file cannot be opened
    
    uint64_t energy;
    int itemRead = fscanf(f, "%lu", &energy);
    if (itemRead != 1) {
        fclose(f);
        return -1; // Return -1 if reading fails
    }
    fclose(f);
    return energy;
}

void calcStats(struct stats* st, double total_time, double* time_mesurements, uint64_t total_energy) {

    // Calculate power consumed in watts (W) using the formula: Power (W) = Energy (J) / Time (s)
    double power_consumed = 0.0;
    if (total_time > 0) {
        power_consumed = (double)total_energy / total_time / 1e6; 
    }

    // Calculate the average time for the operation
    st->average_time = total_time / TEST_NUMBER;

    // Calculate the standard deviation of the time measurements
    double sum_squared_diff = 0.0;
    for (int i = 0; i < TEST_NUMBER; i++) {
        double diff = time_mesurements[i] - st->average_time;
        sum_squared_diff += diff * diff;
    }
    st->time_standard_deviation = sqrt(sum_squared_diff / TEST_NUMBER);

    st->elapsed_time = total_time;
    st->energy_consumed = total_energy;
    st->power_consumed = power_consumed;
}

void saveStatsToFile(struct stats* stEnc, struct stats* stDec, char* filename, const char* alg_name, ChaosMap mapUsed) {
    FILE* file = fopen(filename, "a");
    if (file == NULL) {
        perror("Errore nell'apertura del file");
        return;
    }

    size_t heap_consumed = (mapUsed != NONE) ? AES_CHAOS_get_heap_size(mapUsed) : 0;

    fprintf(file, "%s,%s,%d,%f,%f,%f,%lu,%f,!,%zu\n",
            alg_name, "Cifratura", TEST_NUMBER, 
            stEnc->elapsed_time, stEnc->average_time, stEnc->time_standard_deviation, stEnc->energy_consumed, stEnc->power_consumed,heap_consumed);

    fprintf(file, "%s,%s,%d,%f,%f,%f,%lu,%f,!,%zu\n",
            alg_name, "Decifratura", TEST_NUMBER, 
            stDec->elapsed_time, stDec->average_time, stDec->time_standard_deviation, stDec->energy_consumed, stDec->power_consumed, heap_consumed);

    

    fclose(file);
}

void benchmark(struct stats* chypherStats, struct stats* decypherStats, const char* alg_name, uint8_t* text, uint8_t* key, uint8_t* iv, uint8_t* aad) {

    // Inizialization of AES context for GCM mode
    struct AES_ctx ctx_gcm;
    AES_init_ctx_iv(&ctx_gcm, key, iv);

    // Prepare the result structure for GCM encryption
    struct AES_GCM_result buffer;
    buffer.buf = (uint8_t*)malloc(TEXT_LENGTH * sizeof(uint8_t));
    memcpy(buffer.buf, text, TEXT_LENGTH);

    /*****************************************************************************/
    /* Encrypt Start mesurements                                                 */
    
    // Allocate memory for time measurements for each iteration
    double* time_measurements = (double*)malloc(TEST_NUMBER * sizeof(double)); // Array to store time measurements for each iteration

    // Variable to store the current time for each iteration
    double current_time = 0.0;

    // Variable to accumulate total time for multiple iterations
    double total_time = 0.0;

    // Variable to accumulate total energy consumed for multiple iterations
    uint64_t total_energy = 0;

    // variables to measure time consumption
    struct timespec start, end;


    for(int i = 0; i < TEST_NUMBER; i++) {

        // Reset the AES context and IV for each iteration
        memcpy(buffer.buf, text, TEXT_LENGTH);
        AES_ctx_set_iv(&ctx_gcm, iv);

        // Measure the energy consumption before encryption and authentication
        uint64_t energy_start = read_energy();

        // Measure the start time for encryption and authentication
        clock_gettime(CLOCK_MONOTONIC, &start);

        // Encryption and authentication using AES-GCM
        AES_GCM_authenticated_encrypt_buffer(&ctx_gcm, &buffer, TEXT_LENGTH, 12, aad, AAD_LENGTH);

        // Measure the end time for encryption and authentication
        clock_gettime(CLOCK_MONOTONIC, &end);

        // Measure the energy consumption after encryption and authentication
        uint64_t energy_end = read_energy();

        // Calculate the elapsed time for this iteration
        current_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        // Store the time measurement for this iteration
        time_measurements[i] = current_time; 

        // Calculate the elapsed time for this iteration
        total_time += current_time;

        // Calculate the energy consumed for this iteration, handling potential overflow
        if (energy_end < energy_start) {
            uint64_t max_energy = read_max_energy();
            total_energy += (max_energy - energy_start) + energy_end;
        } else {
            total_energy += energy_end - energy_start;
        }
    }

    /* Encrypt End mesurements                                                   */
    /*****************************************************************************/
    

    calcStats(chypherStats, total_time, time_measurements, total_energy);


    /*****************************************************************************/
    /* Decrypt Start mesurements                                                 */

    // Reset time measurements for decryption
    memset(time_measurements, 0, TEST_NUMBER * sizeof(double)); 

    // Reset total time for decryption measurements
    total_time = 0.0; 

    // Reset total energy for decryption measurements
    total_energy = 0;

    // variables to measure time consumption
    int authentication_errors = 0;

    memcpy(text, buffer.buf, TEXT_LENGTH); // Reset the text buffer to the original ciphertext for decryption

    for(int i = 0; i < TEST_NUMBER; i++) {

        // Reset the AES context and IV for each iteration
        memcpy(buffer.buf, text, TEXT_LENGTH);
        AES_ctx_set_iv(&ctx_gcm, iv);

        // Measure the energy consumption before decryption and authentication
        uint64_t energy_start = read_energy();

        // Measure the start time for decryption and authentication
        clock_gettime(CLOCK_MONOTONIC, &start);

        int is_valid = AES_GCM_authenticated_decrypt_buffer(&ctx_gcm, &buffer, buffer.tag, TEXT_LENGTH, 12, aad, AAD_LENGTH);

        // Measure the end time for decryption and authentication
        clock_gettime(CLOCK_MONOTONIC, &end);

        // Measure the energy consumption after decryption and authentication
        uint64_t energy_end = read_energy();

        if (!is_valid) {
            authentication_errors++;
        }

        // Calculate the elapsed time for this iteration
        current_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        // Store the time measurement for this iteration
        time_measurements[i] = current_time; 

        // Calculate the elapsed time for this iteration
        total_time += current_time;

        // Calculate the energy consumed for this iteration, handling potential overflow
        if (energy_end < energy_start) {
            uint64_t max_energy = read_max_energy();
            total_energy += (max_energy - energy_start) + energy_end;
        } else {
            total_energy += energy_end - energy_start;
        }
    }

    if (authentication_errors > 0) {
        perror("[ERRORE CRITICO] Il tag è stato RIFIUTATO!\n");
        exit(EXIT_FAILURE); // Exit the program if authentication fails
    }


    /* Decrypt End mesurements                                                   */
    /*****************************************************************************/
    
    calcStats(decypherStats, total_time, time_measurements, total_energy);


    saveStatsToFile(chypherStats, decypherStats, FILENAME, alg_name, NONE);

    free(time_measurements); // Free the allocated memory for time measurements
    free(buffer.buf); // Free the allocated memory for the ciphertext buffer
}

void benchmark_chaos(struct stats* chypherStats, struct stats* decypherStats, const char* map_name, uint8_t* text, uint8_t* key, uint8_t* iv, uint8_t* aad, ChaosMap chaos_map) {
    // Inizialization of AES context for GCM mode
    struct AES_CHAOS_ctx ctx_gcm;
    AES_CHAOS_init_ctx_iv(&ctx_gcm, key, iv, chaos_map);

    // Prepare the result structure for GCM encryption
    struct AES_CHAOS_GCM_result buffer;
    buffer.buf = (uint8_t*)malloc(TEXT_LENGTH * sizeof(uint8_t));
    memcpy(buffer.buf, text, TEXT_LENGTH);

    /*****************************************************************************/
    /* Encrypt Start mesurements                                                 */
    
    // Allocate memory for time measurements for each iteration
    double* time_measurements = (double*)malloc(TEST_NUMBER * sizeof(double)); // Array to store time measurements for each iteration

    // Variable to store the current time for each iteration
    double current_time = 0.0;

    // Variable to accumulate total time for multiple iterations
    double total_time = 0.0;

    // Variable to accumulate total energy consumed for multiple iterations
    uint64_t total_energy = 0;

    // variables to measure time consumption
    struct timespec start, end;


    for(int i = 0; i < TEST_NUMBER; i++) {

        // Reset the AES context and IV for each iteration
        memcpy(buffer.buf, text, TEXT_LENGTH);
        AES_CHAOS_ctx_set_iv(&ctx_gcm, iv);

        // Measure the energy consumption before encryption and authentication
        uint64_t energy_start = read_energy();

        // Measure the start time for encryption and authentication
        clock_gettime(CLOCK_MONOTONIC, &start);

        // Encryption and authentication using AES-GCM
        AES_CHAOS_GCM_authenticated_encrypt_buffer(&ctx_gcm, &buffer, TEXT_LENGTH, 12, aad, AAD_LENGTH);

        // Measure the end time for encryption and authentication
        clock_gettime(CLOCK_MONOTONIC, &end);

        // Measure the energy consumption after encryption and authentication
        uint64_t energy_end = read_energy();

        // Calculate the elapsed time for this iteration
        current_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        // Store the time measurement for this iteration
        time_measurements[i] = current_time; 

        // Calculate the elapsed time for this iteration
        total_time += current_time;

        // Calculate the energy consumed for this iteration, handling potential overflow
        if (energy_end < energy_start) {
            uint64_t max_energy = read_max_energy();
            total_energy += (max_energy - energy_start) + energy_end;
        } else {
            total_energy += energy_end - energy_start;
        }
    }

    /* Encrypt End mesurements                                                   */
    /*****************************************************************************/


    calcStats(chypherStats, total_time, time_measurements, total_energy);


    /*****************************************************************************/
    /* Decrypt Start mesurements                                                 */

    // Reset time measurements for decryption
    memset(time_measurements, 0, TEST_NUMBER * sizeof(double)); 

    // Reset total time for decryption measurements
    total_time = 0.0; 

    // Reset total energy for decryption measurements
    total_energy = 0;

    // variables to measure time consumption
    int authentication_errors = 0;

    memcpy(text, buffer.buf, TEXT_LENGTH); // Reset the text buffer to the original ciphertext for decryption

    for(int i = 0; i < TEST_NUMBER; i++) {

        // Reset the AES context and IV for each iteration
        memcpy(buffer.buf, text, TEXT_LENGTH);
        AES_CHAOS_ctx_set_iv(&ctx_gcm, iv);

        // Measure the energy consumption before decryption and authentication
        uint64_t energy_start = read_energy();

        // Measure the start time for decryption and authentication
        clock_gettime(CLOCK_MONOTONIC, &start);

        int is_valid = AES_CHAOS_GCM_authenticated_decrypt_buffer(&ctx_gcm, &buffer, buffer.tag, TEXT_LENGTH, 12, aad, AAD_LENGTH);

        // Measure the end time for decryption and authentication
        clock_gettime(CLOCK_MONOTONIC, &end);

        // Measure the energy consumption after decryption and authentication
        uint64_t energy_end = read_energy();

        if (!is_valid) {
            authentication_errors++;
        }

        // Calculate the elapsed time for this iteration
        current_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        // Store the time measurement for this iteration
        time_measurements[i] = current_time; 

        // Calculate the elapsed time for this iteration
        total_time += current_time;

        // Calculate the energy consumed for this iteration, handling potential overflow
        if (energy_end < energy_start) {
            uint64_t max_energy = read_max_energy();
            total_energy += (max_energy - energy_start) + energy_end;
        } else {
            total_energy += energy_end - energy_start;
        }
    }

    if (authentication_errors > 0) {
        perror("[ERRORE CRITICO] Il tag è stato RIFIUTATO!\n");
        exit(EXIT_FAILURE); // Exit the program if authentication fails
    }



    /* Decrypt End mesurements                                                   */
    /*****************************************************************************/
    
    calcStats(decypherStats, total_time, time_measurements, total_energy);


    saveStatsToFile(chypherStats, decypherStats, FILENAME, map_name, chaos_map);

    free(time_measurements); // Free the allocated memory for time measurements
    free(buffer.buf); // Free the allocated memory for the ciphertext buffer
    free(ctx_gcm.map_state); // Free the allocated memory for the chaotic map state
}
