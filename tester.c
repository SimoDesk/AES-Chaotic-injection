#include "tester.h"

// Counter of the number of tests performed
static int test_done = 0;

// Fill the buffer with random values
void getRandomValue(uint8_t* buf, size_t buf_size) {
    for (size_t i = 0; i < buf_size; i++) {
        buf[i] = (uint8_t)(rand() % 256);
    }
}

// Read the energy consumption from the specified file and return it as a uint64_t value
uint64_t read_energy() {
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

void calcStats(struct stats* st, struct timespec start, struct timespec end, uint64_t energy_start, uint64_t energy_end) {

    // Calculate the elapsed time in seconds
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    // Calculate the energy consumed in microjoules
    uint64_t energy_consumed = energy_end - energy_start;

    // Calculate the power consumed in watts
    double power_consumed = (double)energy_consumed / elapsed_time / 1e6; // Convert microjoules to joules

    st->elapsed_time = elapsed_time;
    st->energy_consumed = energy_consumed;
    st->power_consumed = power_consumed;
}

void saveStatsToFile(struct stats* stEnc, struct stats* stDec, const char* filename, const char* alg_name) {
    FILE* file = fopen(filename, "a");
    if (file == NULL) {
        perror("Errore nell'apertura del file");
        return;
    }

    fprintf(file, "=== TEST %s, %i iterazioni ===\n", alg_name, TEST_NUMBER);
    fprintf(file, "Tempo impiegato per cifratura e autenticazione: %.6f secondi\n", stEnc->elapsed_time);
    fprintf(file, "Energia consumata per cifratura e autenticazione: %lu microjoules\n", stEnc->energy_consumed);
    fprintf(file, "Potenza consumata per cifratura e autenticazione: %.6f W\n", stEnc->power_consumed);
    fprintf(file, "*memoryEnc_%i*\n", test_done);

    fprintf(file, "---------------------------\n");

    fprintf(file, "Tempo impiegato per decifratura e autenticazione: %.6f secondi\n", stDec->elapsed_time);
    fprintf(file, "Energia consumata per decifratura e autenticazione: %lu microjoules\n", stDec->energy_consumed);
    fprintf(file, "Potenza consumata per decifratura e autenticazione: %.6f W\n", stDec->power_consumed);
    fprintf(file, "*memoryDec_%i*\n", test_done++);

    fprintf(file, "=============================================\n\n");

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
    
    // variables to measure time consumption
    struct timespec start, end;

    // Measure the start time for encryption and authentication
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Measure the energy consumption before encryption and authentication
    uint64_t energy_start = read_energy();

    /*****************************************************************************/



    for(int i = 0; i < TEST_NUMBER; i++) {

        // Reset the AES context and IV for each iteration
        memcpy(buffer.buf, text, TEXT_LENGTH);
        AES_ctx_set_iv(&ctx_gcm, iv);

        // Encryption and authentication using AES-GCM
        AES_GCM_authenticated_encrypt_buffer(&ctx_gcm, &buffer, TEXT_LENGTH, 12, aad, AAD_LENGTH);
    }



    /*****************************************************************************/
    /* Encrypt End mesurements                                                   */

    // Measure the end time for encryption and authentication
    clock_gettime(CLOCK_MONOTONIC, &end);

    // Measure the energy consumption after encryption and authentication
    uint64_t energy_end = read_energy();

    /*****************************************************************************/

    calcStats(chypherStats, start, end, energy_start, energy_end);



    /*****************************************************************************/
    /* Decrypt Start mesurements                                                 */

    // Measure the start time for encryption and authentication
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Measure the energy consumption before encryption and authentication
    energy_start = read_energy();

    /*****************************************************************************/


    int authentication_errors = 0;

    memcpy(text, buffer.buf, TEXT_LENGTH); // Reset the text buffer to the original ciphertext for decryption

    for(int i = 0; i < TEST_NUMBER; i++) {

        // Reset the AES context and IV for each iteration
        memcpy(buffer.buf, text, TEXT_LENGTH);
        AES_ctx_set_iv(&ctx_gcm, iv);

        int is_valid = AES_GCM_authenticated_decrypt_buffer(&ctx_gcm, &buffer, buffer.tag, TEXT_LENGTH, 12, aad, AAD_LENGTH);

        if (!is_valid) {
            authentication_errors++;
        }
    }

    if (authentication_errors > 0) {
        printf("[ERRORE CRITICO] Il tag manomesso è stato accettato!\n");
    }



    /*****************************************************************************/
    /* Decrypt End mesurements                                                   */

    // Measure the end time for encryption and authentication
    clock_gettime(CLOCK_MONOTONIC, &end);

    // Measure the energy consumption after encryption and authentication
    energy_end = read_energy();

    /*****************************************************************************/



    /*****************************************************************************/
    /* Encrypt mesurements calculations                                          */

    calcStats(decypherStats, start, end, energy_start, energy_end);


    saveStatsToFile(chypherStats, decypherStats, "results.txt", alg_name);
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
    
    // variables to measure time consumption
    struct timespec start, end;

    // Measure the start time for encryption and authentication
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Measure the energy consumption before encryption and authentication
    uint64_t energy_start = read_energy();

    /*****************************************************************************/



    for(int i = 0; i < TEST_NUMBER; i++) {

        // Reset the AES context and IV for each iteration
        memcpy(buffer.buf, text, TEXT_LENGTH);
        AES_CHAOS_ctx_set_iv(&ctx_gcm, iv);

        // Encryption and authentication using AES-GCM
        AES_CHAOS_GCM_authenticated_encrypt_buffer(&ctx_gcm, &buffer, TEXT_LENGTH, 12, aad, AAD_LENGTH);
    }



    /*****************************************************************************/
    /* Encrypt End mesurements                                                   */

    // Measure the end time for encryption and authentication
    clock_gettime(CLOCK_MONOTONIC, &end);

    // Measure the energy consumption after encryption and authentication
    uint64_t energy_end = read_energy();

    /*****************************************************************************/

    calcStats(chypherStats, start, end, energy_start, energy_end);



    /*****************************************************************************/
    /* Decrypt Start mesurements                                                 */

    // Measure the start time for encryption and authentication
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Measure the energy consumption before encryption and authentication
    energy_start = read_energy();

    /*****************************************************************************/


    int authentication_errors = 0;

    memcpy(text, buffer.buf, TEXT_LENGTH); // Reset the text buffer to the original ciphertext for decryption

    for(int i = 0; i < TEST_NUMBER; i++) {

        // Reset the AES context and IV for each iteration
        memcpy(buffer.buf, text, TEXT_LENGTH);
        AES_CHAOS_ctx_set_iv(&ctx_gcm, iv);

        int is_valid = AES_CHAOS_GCM_authenticated_decrypt_buffer(&ctx_gcm, &buffer, buffer.tag, TEXT_LENGTH, 12, aad, AAD_LENGTH);

        if (!is_valid) {
            authentication_errors++;
        }
    }

    if (authentication_errors > 0) {
        printf("[ERRORE CRITICO] Il tag manomesso è stato accettato!\n");
    }



    /*****************************************************************************/
    /* Decrypt End mesurements                                                   */

    // Measure the end time for encryption and authentication
    clock_gettime(CLOCK_MONOTONIC, &end);

    // Measure the energy consumption after encryption and authentication
    energy_end = read_energy();

    /*****************************************************************************/



    /*****************************************************************************/
    /* Encrypt mesurements calculations                                          */

    calcStats(decypherStats, start, end, energy_start, energy_end);


    saveStatsToFile(chypherStats, decypherStats, "results.txt", map_name);
}
