#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../aes_default/aes.h"
#include "../aes_chaos/aes_chaos.h"

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

#define TEXT_LENGTH 16 // Length of the plaintext in bytes

int main(int argc, char *argv[])
{
    if (argc < 6) {
        printf("Args error");
        return EXIT_FAILURE;
    }

    // Convert input hex strings to byte arrays
    uint8_t text[16];
    uint8_t iv[12];
    uint8_t key[32];

    ChaosMap map_type = NONE; // Default map type is NONE
    map_type = parseMapType(argv[1]);

    hex_to_bytes(argv[2], text, 16);
    hex_to_bytes(argv[3], iv, 12);
    hex_to_bytes(argv[4], key, 32);
    int n_test = atoi(argv[5]);

    struct AES_ctx ctx_std;
    struct AES_CHAOS_ctx ctx_chaos;

    if (map_type != NONE) {
        AES_CHAOS_init_ctx(&ctx_chaos, key, map_type);
    } else {
        AES_init_ctx_iv(&ctx_std, key, iv);
    }

    struct AES_GCM_result res_std = {.buf = text};
    struct AES_CHAOS_GCM_result res_chaos = {.buf = text};

    if (argc == 8) {
        AES_CHAOS_ctx_set_params(&ctx_chaos, atof(argv[6]), atof(argv[7]));
    }

    if (map_type != NONE) {
        AES_CHAOS_ECB_encrypt(&ctx_chaos, text);
        AES_CHAOS_free_ctx(&ctx_chaos);
    } else {
        AES_ECB_encrypt(&ctx_std, text);
    }

    char filename[256];
    int path_length = snprintf(filename, sizeof(filename), "cipher_%i.bin", n_test);
    if (path_length < 0 || (size_t)path_length >= sizeof(filename)) {
        fprintf(stderr, "Percorso del file di output troppo lungo\n");

        return EXIT_FAILURE;
    }

    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Errore nell'apertura del file");

        return EXIT_FAILURE;
    }

    // Write the ciphertext to the file
    size_t written = (map_type != NONE) ? fwrite(res_chaos.buf, sizeof(uint8_t), TEXT_LENGTH, file) : fwrite(res_std.buf, sizeof(uint8_t), TEXT_LENGTH, file);
    if (written != (size_t)TEXT_LENGTH) {
        perror("Errore nella scrittura del file");
        fclose(file);

        return EXIT_FAILURE;
    }

    fclose(file);

    return 0;
}