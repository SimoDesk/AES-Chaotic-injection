#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../aes_default/aes.h"
#include "../aes_chaos/aes_chaos.h"
#include "../tester.h"

// Function to parse the map type from a string
ChaosMap parseMapType(const char* map_str) {
    if (strcmp(map_str, "logistic") == 0) return LOGISTIC_MAP;
    if (strcmp(map_str, "tent") == 0) return TENT_MAP;
    if (strcmp(map_str, "henon") == 0) return HENON_MAP;
    if (strcmp(map_str, "arnold") == 0) return ARNOLD_CAT_MAP;
    if (strcmp(map_str, "sine") == 0) return SINE_MAP;
    if (strcmp(map_str, "lorenz") == 0) return LORENZ_MAP;
    if (strcmp(map_str, "chen") == 0) return CHEN_MAP;
    if (strcmp(map_str, "rossler") == 0) return ROSSLER_MAP;
    return NONE;
}

int main(int argc, char *argv[])
{

    ChaosMap map_type = NONE; // Default map type is NONE

    if (argc > 1) {
        map_type = parseMapType(argv[1]);
    }

    unsigned int seed = 06102026;
    srand(seed); // Set the initial seed for rand() function

    uint8_t* key = malloc(AES_KEYLEN * sizeof(uint8_t));
    getRandomValue(key, AES_KEYLEN);

    uint8_t* iv = malloc(AES_IVLEN * sizeof(uint8_t));
    getRandomValue(iv, AES_IVLEN);

    uint8_t* text = malloc(TEXT_LENGTH * sizeof(uint8_t));
    memset(text, 0, TEXT_LENGTH); // Initialize the text buffer with zeros

    uint8_t* aad = malloc(AAD_LENGTH * sizeof(uint8_t));
    getRandomValue(aad, AAD_LENGTH);

    struct AES_ctx ctx_std;
    struct AES_CHAOS_ctx ctx_chaos;

    if (map_type != NONE) {
        AES_CHAOS_init_ctx_iv(&ctx_chaos, key, iv, map_type);
    } else {
        AES_init_ctx_iv(&ctx_std, key, iv);
    }

    struct AES_GCM_result res_std = {.buf = text};
    struct AES_CHAOS_GCM_result res_chaos = {.buf = text};


    if (map_type != NONE) {
        AES_CHAOS_GCM_authenticated_encrypt_buffer(&ctx_chaos, &res_chaos, TEXT_LENGTH, AES_IVLEN, aad, AAD_LENGTH);
    } else {
        AES_GCM_authenticated_encrypt_buffer(&ctx_std, &res_std, TEXT_LENGTH, AES_IVLEN, aad, AAD_LENGTH);
    }

    time_t now;
    time(&now);

    struct tm *local = localtime(&now);

    char* timestamp = malloc(20 * sizeof(char));
    strftime(timestamp, 20, "_%d-%m-%Y_%H:%M", local);

    char* filename = calloc(100, sizeof(char));

    strcat(filename, "cipher_");
    strcat(filename, argv[1]);
    strcat(filename, timestamp);
    strcat(filename, ".bin");

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Errore nell'apertura del file");
        return -1;
    }

    // Write the ciphertext to the file
    size_t written = (map_type != NONE) ? fwrite(res_chaos.buf, sizeof(uint8_t), TEXT_LENGTH, file) : fwrite(res_std.buf, sizeof(uint8_t), TEXT_LENGTH, file);
    if (written != TEXT_LENGTH) {
        perror("Errore nella scrittura del file");
        fclose(file);
        return -1;
    }

    fclose(file);

    free(key);
    free(iv);
    free(text);
    free(aad);
    free(timestamp);
    free(filename);

    return 0;
}