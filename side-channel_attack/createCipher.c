#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../aes_default/aes.h"
#include "../aes_chaos/aes_chaos.h"

#include "../testBenchmark/tester.h"

// Function to parse the map type from a string
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

// Function to convert a hexadecimal string to a byte array
void hex_to_bytes(const char* hex_str, uint8_t* byte_array, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &byte_array[i]);
    }
}

#define PAYLOAD_LENGTH 256 // Length of the plaintext in bytes

int main(int argc, char *argv[])
{
    ChaosMap map_type = NONE; // Default map type is NONE

    if (argc > 1) {
        map_type = parseMapType(argv[1]);
    }
    
    unsigned int seed = 391356;
    srand(seed); // Set the initial seed for rand() function

    uint8_t* key = malloc(AES_KEYLEN * sizeof(uint8_t));
    getRandomValue(key, AES_KEYLEN);

    uint8_t* text = malloc(PAYLOAD_LENGTH * sizeof(uint8_t));

    uint8_t* aad = malloc(AAD_LENGTH * sizeof(uint8_t));

    uint8_t* iv = malloc(AES_IVLEN * sizeof(uint8_t));

    
    FILE *file = NULL;

    uint8_t* tag = malloc(GCM_TAGLEN * sizeof(uint8_t));

    struct AES_GCM_attack_result* attack_res = NULL;

    for (int phase = 0; phase < 2; phase++) {

        int packet_quantity = 15000;

        if (phase == 0) {
            // Only if we are in the profiling phase, we create the training data file containing the hamming weights and target bytes for both rounds of AES-GCM encryption.

            file = fopen("data/training_data.csv", "w");
            if (file != NULL) {
                fprintf(file, "Map,IV,");
                // Round 1
                for (int i = 0; i < AES_BLOCKLEN; i++) fprintf(file, "HW_P1_%d,", i);
                for (int i = 0; i < AES_BLOCKLEN; i++) fprintf(file, "Target_P1_%d,", i);
                // Round 2
                for (int i = 0; i < AES_BLOCKLEN; i++) fprintf(file, "HW_P2_%d,", i);
                for (int i = 0; i < AES_BLOCKLEN; i++) fprintf(file, "Target_P2_%d%s", i, (i == AES_BLOCKLEN - 1) ? "" : ",");
                
                fprintf(file, "\n");
            }
        } else {
            // If we are in the attack phase, we create a separate file to store only the hamming weights and target bytes for both rounds of AES-GCM encryption, which will be used for the attack.

            if (file != NULL) {
                fclose(file);
            }
            file = fopen("data/attack_data.csv", "w");
            if (file != NULL) {
                fprintf(file, "Map,IV,");
                // Round 1
                for (int i = 0; i < AES_BLOCKLEN; i++) fprintf(file, "HW_P1_%d,", i);
                // Round 2
                for (int i = 0; i < AES_BLOCKLEN; i++) fprintf(file, "HW_P2_%d,", i);
                
                fprintf(file, "\n");
            }

            // Quick key
            // hex_to_bytes("00112233445566778899aabb00001000ccddeeff00112233445566778899aabb", key, AES_KEYLEN);

            getRandomValue(key, AES_KEYLEN);

            packet_quantity = 100;

        }

        for (int packet_index = 0; packet_index < packet_quantity; packet_index++) {
            // Generate a new random plaintext for each packet
            getRandomValue(text, PAYLOAD_LENGTH);

            // Generate a new random AAD for each packet
            getRandomValue(aad, AAD_LENGTH);

            // Generate a new random IV for each packet
            getRandomValue(iv, AES_IVLEN);

            struct AES_GCM_result res_std;
            struct AES_CHAOS_GCM_result res_chaos;

            // Depending on the specified chaos map type, initialize the appropriate AES-GCM context (standard or chaotic)
            // and perform the authenticated encryption of the plaintext with the given key, IV, AAD, and tag length. 
            // The results will be stored in the corresponding result structures.
            if (map_type == NONE) {
                struct AES_GCM_ctx ctx_std;

                AES_GCM_init_ctx(&ctx_std, key);

                AES_GCM_set_iv(&ctx_std, iv, AES_IVLEN);

                res_std.buf = text;
                res_std.tag = tag;

                AES_GCM_authenticated_encrypt_buffer(&ctx_std, &res_std, PAYLOAD_LENGTH, aad, AAD_LENGTH, GCM_TAGLEN);

                attack_res = get_attack_result();

                AES_GCM_free_ctx(&ctx_std);
            } else {
                struct AES_CHAOS_GCM_ctx ctx_chaos;

                AES_CHAOS_GCM_init_ctx(&ctx_chaos, key, map_type);
                AES_CHAOS_GCM_set_iv(&ctx_chaos, iv, AES_IVLEN);

                res_chaos.buf = text;
                res_chaos.tag = tag;

                AES_CHAOS_GCM_authenticated_encrypt_buffer(&ctx_chaos, &res_chaos, PAYLOAD_LENGTH, aad, AAD_LENGTH, GCM_TAGLEN);

                attack_res = (struct AES_GCM_attack_result*) get_chaos_attack_result();

                AES_CHAOS_GCM_free_ctx(&ctx_chaos);
            }

            // Save all the relevant information (map type, IV, hamming weights, and target bytes) to the CSV depending on the phase (profiling or attack).
            if (file != NULL && attack_res != NULL) {
                fprintf(file, "%s,", map_type == NONE ? "std" : argv[1]);

                for (int j = 0; j < AES_IVLEN; j++) {
                    fprintf(file, "%02x", iv[j]);
                }
                fprintf(file, ",");

                // Print HW and Target Round 1
                for (int j = 0; j < AES_BLOCKLEN; j++) 
                    fprintf(file, "%d,", attack_res->hamming_weight_p1[j]);

                if (phase == 0)
                    for (int j = 0; j < AES_BLOCKLEN; j++) 
                        fprintf(file, "%d,", attack_res->target_bytes_p1[j]);

                // Print HW and Target Round 2
                for (int j = 0; j < AES_BLOCKLEN; j++) 
                    fprintf(file, "%d,", attack_res->hamming_weight_p2[j]);

                if (phase == 0) 
                    for (int j = 0; j < AES_BLOCKLEN; j++) {
                        fprintf(file, "%d%s", attack_res->target_bytes_p2[j], (j == AES_BLOCKLEN - 1) ? "" : ",");
                    }
                

                fprintf(file, "\n");
            }

            // Restart the attack simulation for the next packet
            if (map_type == NONE)
                restart_attack_simulation();
            else
                restart_chaos_attack_simulation();

            // Print the key, IV, ciphertext, AAD, and tag for the first packet in the attack phase for verification purposes.
            if (packet_index == 0 && phase == 1) {
                printf("KEY="); for(int j=0; j<AES_KEYLEN; j++) printf("%02x", key[j]); printf("\n");
                printf("TARGET_IV="); for(int j=0; j<AES_IVLEN; j++) printf("%02x", iv[j]); printf("\n");
                printf("TARGET_CIPHER="); for(int j=0; j<PAYLOAD_LENGTH; j++) printf("%02x", text[j]); printf("\n");
                printf("TARGET_AAD="); for(int j=0; j<AAD_LENGTH; j++) printf("%02x", aad[j]); printf("\n");
                printf("TARGET_TAG="); for(int j=0; j<GCM_TAGLEN; j++) printf("%02x", tag[j]); printf("\n");
                printf("----------------------------------------\n");
            }

        }
    }
    if (file != NULL) {
        fclose(file);
    }

    return 0;
}