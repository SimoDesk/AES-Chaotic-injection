#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <omp.h>

// Importiamo le tue implementazioni
#include "../aes_default/aes.h"
#include "../aes_chaos/aes_chaos.h"

#define PAYLOAD_LENGTH 256

// CandidateTuple structure to hold the candidate bytes for K1 and K2
typedef struct {
    uint8_t k1;
    uint8_t k2_0, k2_1, k2_2, k2_3;
} CandidateTuple;

// loadCandidates function to read candidate tuples from a binary file and populate the array of CandidateTuple structures. Each tuple consists of one byte for K1 and four bytes for K2.
void loadCandidates(const char *filename, CandidateTuple *list) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Unable to open %s\n", filename);
        exit(1);
    }

    // For each of the 256 possible guesses for K1, read 5 bytes from the file: 1 byte for K1 and 4 bytes for K2. Store these bytes in the corresponding fields of the CandidateTuple structure.
    for (int i = 0; i < 256; i++) {
        uint8_t buf[5];
        
        // Read 5 bytes from the binary file into the buffer. If fewer than 5 bytes are read, break the loop as it indicates the end of the file or an error.
        size_t bytes_read = fread(buf, 1, 5, file);
        if (bytes_read != 5) break;
        
        // Assign the read bytes to the corresponding fields of the CandidateTuple structure in the list.
        list[i].k1 = buf[0];
        list[i].k2_0 = buf[1];
        list[i].k2_1 = buf[2];
        list[i].k2_2 = buf[3];
        list[i].k2_3 = buf[4];
    }
    fclose(file);
}

// Function to convert a hexadecimal string to a byte array
void hex_to_bytes(const char* hex_str, uint8_t* byte_array, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &byte_array[i]);
    }
}

// Function to parse the chaos map type from a string
ChaosMap parseMapType(const char* map_str) {
    if (strcmp(map_str, "logistic") == 0) return LOGISTIC_MAP;
    if (strcmp(map_str, "tent") == 0) return TENT_MAP;
    if (strcmp(map_str, "henon") == 0) return HENON_MAP;
    if (strcmp(map_str, "arnold") == 0) return ARNOLD_CAT_MAP;
    if (strcmp(map_str, "sine") == 0) return SINE_MAP;
    if (strcmp(map_str, "chebyshev") == 0) return CHEBYSHEV_MAP;
    if (strcmp(map_str, "lorenz") == 0) return LORENZ_MAP;
    if (strcmp(map_str, "chen") == 0) return CHEN_MAP;
    if (strcmp(map_str, "rossler") == 0) return ROSSLER_MAP;
    return NONE;
}

int main(int argc, char *argv[]) {
    if (argc < 7) {
        printf("Args error");
        return 1;
    }

    // known_k1 holds the first 12 bytes of the key that were extracted from the side-channel attack.
    uint8_t known_k1[12];
    hex_to_bytes(argv[1], known_k1, 12);
    
    // Parse the chaos map type from the command-line argument. This determines which chaotic mapping will be used during the brute-force search.
    ChaosMap map_type = parseMapType(argv[2]);
    
    // target_iv holds the initialization vector (IV) used for AES-GCM encryption of the target ciphertext. It is provided as a command-line argument in hexadecimal format.
    uint8_t target_iv[AES_IVLEN]; 
    hex_to_bytes(argv[3], target_iv, AES_IVLEN);

    // target_ciphertext holds the ciphertext that we are trying to decrypt using the brute-force search. It is provided as a command-line argument in hexadecimal format.
    uint8_t target_ciphertext[PAYLOAD_LENGTH];
    hex_to_bytes(argv[4], target_ciphertext, PAYLOAD_LENGTH);

    // target_aad holds the additional authenticated data (AAD) used during AES-GCM encryption. It is provided as a command-line argument in hexadecimal format.
    uint8_t target_aad[AAD_LENGTH];
    hex_to_bytes(argv[5], target_aad, AAD_LENGTH);

    // target_tag holds the authentication tag generated during AES-GCM encryption. It is provided as a command-line argument in hexadecimal format and will be used to verify the correctness of the decrypted plaintext.
    uint8_t target_tag[GCM_TAGLEN];
    hex_to_bytes(argv[6], target_tag, GCM_TAGLEN);

    // Load the candidate tuples for K1 and K2 from the binary files. Each file contains 256 candidate tuples.
    CandidateTuple col0[256], col1[256], col2[256], col3[256];
    loadCandidates("guesses/col0_candidates.bin", col0);
    loadCandidates("guesses/col1_candidates.bin", col1);
    loadCandidates("guesses/col2_candidates.bin", col2);
    loadCandidates("guesses/col3_candidates.bin", col3);

    printf("Starting brute-force search on 4,294,967,296 possible keys...\n");

    volatile bool key_found = false;
    unsigned long long keys_tested = 0;

    // Use OpenMP to parallelize the brute-force search across multiple threads. Each thread will independently test different combinations of candidate bytes for K1 and K2.
    #pragma omp parallel
    {
        // assembled_key will hold the full 32-byte key guess during the brute-force search. It is initialized with the known first 12 bytes of the key.
        uint8_t assembled_key[32];
        memcpy(assembled_key, known_k1, 12);
        
        // thread-local buffer to hold the ciphertext for decryption attempts. This avoids race conditions when multiple threads are decrypting simultaneously.
        uint8_t temp_buf[PAYLOAD_LENGTH];

        // Each thread will iterate over all combinations of candidate bytes for K1 and K2, testing each assembled key against the target ciphertext and tag.
        #pragma omp for schedule(dynamic)

        // Considering all combinatinons, the brute-force search will test 256^4 = 4,294,967,296 possible keys. 
        // Compared with a full AES-256 brute-force search of 2^256 keys, this is a significantly reduced search space due to the information gained from the side-channel attack.

        // For each guess of K1_12, K2_0, K2_1, K2_2, and K2_3...
        for (int i = 0; i < 256; i++) {
            if (key_found) continue;

            assembled_key[15] = col0[i].k1;
            assembled_key[16] = col0[i].k2_0; assembled_key[17] = col0[i].k2_1; 
            assembled_key[18] = col0[i].k2_2; assembled_key[19] = col0[i].k2_3;

            // For each guess of K1_13, K2_4, K2_5, K2_6, and K2_7...
            for (int j = 0; j < 256; j++) {
                if (key_found) break;

                assembled_key[14] = col1[j].k1;
                assembled_key[20] = col1[j].k2_0; assembled_key[21] = col1[j].k2_1; 
                assembled_key[22] = col1[j].k2_2; assembled_key[23] = col1[j].k2_3;

                // For each guess of K1_14, K2_8, K2_9, K2_10, and K2_11...
                for (int k = 0; k < 256; k++) {
                    if (key_found) break;

                    assembled_key[13] = col2[k].k1;
                    assembled_key[24] = col2[k].k2_0; assembled_key[25] = col2[k].k2_1; 
                    assembled_key[26] = col2[k].k2_2; assembled_key[27] = col2[k].k2_3;

                    // For each guess of K1_15, K2_12, K2_13, K2_14, and K2_15...
                    for (int l = 0; l < 256; l++) {
                        if (key_found) break;

                        assembled_key[12] = col3[l].k1;
                        assembled_key[28] = col3[l].k2_0; assembled_key[29] = col3[l].k2_1; 
                        assembled_key[30] = col3[l].k2_2; assembled_key[31] = col3[l].k2_3;
                        
                        // Copy the target ciphertext into the thread-local buffer for decryption attempts. This ensures that each thread works with its own copy of the ciphertext, preventing data races.
                        memcpy(temp_buf, target_ciphertext, PAYLOAD_LENGTH);

                        // auth_success will be set to 1 if the decryption is successful and the authentication tag matches, indicating that the correct key has been found. Otherwise, it will be set to 0.
                        int auth_success = 0;

                        // Depending on the specified chaos map type, initialize the appropriate AES-GCM context (standard or chaotic) 
                        // and attempt to decrypt the target ciphertext using the assembled key. The decryption process will also verify the authentication tag and AAD.
                        if (map_type == NONE) {
                            struct AES_GCM_ctx ctx_std;
                            AES_GCM_init_ctx(&ctx_std, assembled_key);
                            AES_GCM_set_iv(&ctx_std, target_iv, AES_IVLEN);

                            struct AES_GCM_result res_std = {.buf = temp_buf, .tag = NULL};
                            auth_success = AES_GCM_authenticated_decrypt_buffer(&ctx_std, &res_std, PAYLOAD_LENGTH, target_tag, GCM_TAGLEN, target_aad, AAD_LENGTH);
                            
                            AES_GCM_free_ctx(&ctx_std);
                        } else {
                            struct AES_CHAOS_GCM_ctx ctx_chaos;
                            AES_CHAOS_GCM_init_ctx(&ctx_chaos, assembled_key, map_type);
                            AES_CHAOS_GCM_set_iv(&ctx_chaos, target_iv, AES_IVLEN);

                            struct AES_CHAOS_GCM_result res_chaos = {.buf = temp_buf, .tag = NULL};
                            auth_success = AES_CHAOS_GCM_authenticated_decrypt_buffer(&ctx_chaos, &res_chaos, PAYLOAD_LENGTH, target_tag, GCM_TAGLEN, target_aad, AAD_LENGTH);
                            
                            AES_CHAOS_GCM_free_ctx(&ctx_chaos);
                        }

                        // If the decryption is successful and the authentication tag matches, stop the brute-force search by setting the key_found flag to true.
                        // Use a critical section to ensure that only one thread prints the success message, preventing interleaved output.
                        if (auth_success == 1) {
                            key_found = true;
                            #pragma omp critical
                            {
                                printf("\n[!!!] MASTER KEY FOUND [!!!]\n");
                                printf("Tested Keys: %lld\n", keys_tested);
                                printf("Key: ");

                                for(int z=0; z<32; z++) printf("%02x", assembled_key[z]);
                                printf("\n");
                            }
                        }
                    }
                }

                // Update the count of keys tested and print the progress to the terminal. Use atomic capture to safely update the shared keys_tested variable across threads.
                #pragma omp atomic
                keys_tested += 65536;

                // Print the progress to the terminal in a critical section to avoid interleaved output from multiple threads.
                #pragma omp critical
                {
                    printf("\rProgress: %lld/4294967296 keys tested", keys_tested);
                    fflush(stdout);
                }
            }
        }
    }
    
    if (!key_found) {
        printf("\nNo key found after testing %lld keys.\n", keys_tested);
    }
    
    printf("\n");
    return 0;
}