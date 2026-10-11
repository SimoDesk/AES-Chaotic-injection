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

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Uso: %s <mappa> <seed>\n", argv[0]);
        return EXIT_FAILURE;
    }

    ChaosMap map_type = NONE; // Default map type is NONE

    if (argc > 1)
        map_type = parseMapType(argv[1]);

    // Set a default seed for randomness, which can be overridden by a command-line argument
    unsigned int seed = 06102026;
    if (argc > 2)
        seed = (unsigned int)atoi(argv[2]);
  
    srand(seed); // Set the initial seed for rand() function

    // Set the default text length, which can be overridden by a command-line argument
    size_t text_length = 125000;

    uint8_t* key = malloc(AES_KEYLEN * sizeof(uint8_t));
    getRandomValue(key, AES_KEYLEN);

    uint8_t* iv = malloc(AES_IVLEN * sizeof(uint8_t));
    getRandomValue(iv, AES_IVLEN);

    uint8_t* text = malloc(text_length * sizeof(uint8_t));
    memset(text, 0, text_length); // Initialize the text buffer with zeros

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
        AES_CHAOS_GCM_authenticated_encrypt_buffer(&ctx_chaos, &res_chaos, text_length, AES_IVLEN, aad, AAD_LENGTH);
    } else {
        AES_GCM_authenticated_encrypt_buffer(&ctx_std, &res_std, text_length, AES_IVLEN, aad, AAD_LENGTH);
    }

    char filename[256];
    int path_length = snprintf(filename, sizeof(filename), "ciphers/%s/cipher_%s.bin", argv[1], argv[2]);
    if (path_length < 0 || (size_t)path_length >= sizeof(filename)) {
        fprintf(stderr, "Percorso del file di output troppo lungo\n");
        free(key);
        free(iv);
        free(text);
        free(aad);
        return EXIT_FAILURE;
    }

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Errore nell'apertura del file");
        free(key);
        free(iv);
        free(text);
        free(aad);
        return EXIT_FAILURE;
    }

    // Write the ciphertext to the file
    size_t written = (map_type != NONE) ? fwrite(res_chaos.buf, sizeof(uint8_t), text_length, file) : fwrite(res_std.buf, sizeof(uint8_t), text_length, file);
    if (written != text_length) {
        perror("Errore nella scrittura del file");
        fclose(file);
        free(key);
        free(iv);
        free(text);
        free(aad);
        return EXIT_FAILURE;
    }

    fclose(file);

    free(key);
    free(iv);
    free(text);
    free(aad);

    return 0;
}