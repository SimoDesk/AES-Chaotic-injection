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

int main(int argc, char *argv[])
{
    if (argc != 6) {
        printf("Uso: %s <Plaintext 16b> <IV 12b> <Key 32b>\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint8_t text[16];
    uint8_t iv[12];
    uint8_t key[32];

    ChaosMap map_type = NONE; // Default map type is NONE
    map_type = parseMapType(argv[1]);

    hex_to_bytes(argv[2], text, 16);
    hex_to_bytes(argv[3], iv, 12);
    hex_to_bytes(argv[4], key, 32);
    int n_test = atoi(argv[5]);

    int text_length = 16;

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
        AES_CHAOS_ECB_encrypt(&ctx_chaos, text);
    } else {
        AES_ECB_encrypt(&ctx_std, text);
    }

    char filename[256];
    int path_length = snprintf(filename, sizeof(filename), "ciphers/%s/cipher_%i.bin", argv[1], n_test);
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
    size_t written = (map_type != NONE) ? fwrite(res_chaos.buf, sizeof(uint8_t), text_length, file) : fwrite(res_std.buf, sizeof(uint8_t), text_length, file);
    if (written != (size_t)text_length) {
        perror("Errore nella scrittura del file");
        fclose(file);

        return EXIT_FAILURE;
    }

    fclose(file);

    return 0;
}