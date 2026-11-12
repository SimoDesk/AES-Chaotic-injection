#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../aes_default/aes.h"
#include "../aes_chaos/aes_chaos.h"

#define IV_LENGTH 12
#define TAG_LENGTH 16

// Parse the chaotic map type from a string. Returns NONE if the input is invalid.
static ChaosMap parse_map_type(const char *map_name)
{
    if (strcmp(map_name, "none") == 0) return NONE;
    if (strcmp(map_name, "logistic") == 0) return LOGISTIC_MAP;
    if (strcmp(map_name, "tent") == 0) return TENT_MAP;
    if (strcmp(map_name, "henon") == 0) return HENON_MAP;
    if (strcmp(map_name, "arnold") == 0) return ARNOLD_CAT_MAP;
    if (strcmp(map_name, "sine") == 0) return SINE_MAP;
    if (strcmp(map_name, "chebyshev") == 0) return CHEBYSHEV_MAP;
    if (strcmp(map_name, "lorenz") == 0) return LORENZ_MAP;
    if (strcmp(map_name, "chen") == 0) return CHEN_MAP;
    if (strcmp(map_name, "rossler") == 0) return ROSSLER_MAP;
    return NONE;
}

// Print a buffer in hexadecimal format with a label.
static void print_hex(const char *label, const uint8_t *data, size_t length)
{
    printf("%s", label);
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    // Define the plaintext, additional authenticated data (AAD), key, and IV for AES-GCM encryption.
    static const char plaintext[] =
        "SAT-7 telemetry window 2041: the spacecraft is in nominal sun-pointing "
        "attitude and the Ka-band link remains locked with the ground station in "
        "Matera. The flight computer reports stable battery voltage, adequate "
        "thermal margins, and no corrected memory errors during the last pass. "
        "Payload data will be downlinked in two scheduled contact windows; the "
        "receiver shall request a repeat only if the authenticated packet check "
        "fails.";
    static const uint8_t aad[] =
        "SAT-7|pass=2041|ground-station=Matera|band=Ka|channel=telemetry|"
        "priority=nominal|counter=000184";
    const uint8_t key[AES_CHAOS_KEYLEN] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    const uint8_t iv[IV_LENGTH] =
        { 0x8e, 0x99, 0x2c, 0x4a, 0x17, 0x06, 0x55, 0x21, 0x44, 0x90, 0x0b, 0x73 };

    const size_t plaintext_length = sizeof(plaintext) - 1;
    const size_t aad_length = sizeof(aad) - 1;

    uint8_t *ciphertext = NULL;

    uint8_t tag[TAG_LENGTH];

    ChaosMap map_type;

    int valid;

    if (argc != 2) {
        return EXIT_FAILURE;
    }

    // Parse the chaotic map type from the command line argument and allocate memory for the ciphertext.
    map_type = parse_map_type(argv[1]);
    ciphertext = malloc(plaintext_length);
    if (ciphertext == NULL) {
        perror("error allocating memory for ciphertext");
        return EXIT_FAILURE;
    }
    memcpy(ciphertext, plaintext, plaintext_length);

    printf("Chaotic map: %s\n", argv[1]);
    printf("Plaintext (%zu byte): %s\n", plaintext_length, plaintext);
    printf("AAD (%zu byte): %s\n", aad_length, aad);

    // start the random number generator to flip a random bit in the ciphertext or tag to simulate a channel error.
    srand((unsigned)time(NULL));
    {
        // Randomly flip a bit in the ciphertext or tag to simulate a channel error.
        size_t flipped_bit = (size_t)rand() % ((plaintext_length + TAG_LENGTH) * 8);
        size_t byte_index = flipped_bit / 8;
        uint8_t bit_mask = (uint8_t)(1u << (flipped_bit % 8));

        // Encrypt the plaintext with AES-GCM or AES-CHAOS-GCM based on the selected chaotic map type.
        memcpy(ciphertext, plaintext, plaintext_length);
        if (map_type == NONE) {
            struct AES_GCM_ctx ctx;
            struct AES_GCM_result result = { .buf = ciphertext, .tag = tag };
            AES_GCM_init_ctx(&ctx, key);
            if (!AES_GCM_set_iv(&ctx, iv, IV_LENGTH)) {
                fprintf(stderr, "Errore nell'impostazione dell'IV AES-GCM.\n");
                AES_GCM_free_ctx(&ctx);
                free(ciphertext);
                return EXIT_FAILURE;
            }
            AES_GCM_authenticated_encrypt_buffer(&ctx, &result, plaintext_length,
                                                 (uint8_t *)aad, aad_length, TAG_LENGTH);
            AES_GCM_free_ctx(&ctx);
        } else {
            struct AES_CHAOS_GCM_ctx ctx;
            struct AES_CHAOS_GCM_result result = { .buf = ciphertext, .tag = tag };
            AES_CHAOS_GCM_init_ctx(&ctx, key, map_type);
            if (!AES_CHAOS_GCM_set_iv(&ctx, iv, IV_LENGTH)) {
                fprintf(stderr, "GCM-GCM CHAOS: Error setting IV.\n");
                AES_CHAOS_GCM_free_ctx(&ctx);
                free(ciphertext);
                return EXIT_FAILURE;
            }
            AES_CHAOS_GCM_authenticated_encrypt_buffer(&ctx, &result, plaintext_length,
                                                       (uint8_t *)aad, aad_length, TAG_LENGTH);
            AES_CHAOS_GCM_free_ctx(&ctx);
        }

        // Flip the selected bit in the ciphertext or tag to simulate a channel error.
        if (byte_index < plaintext_length) {
            ciphertext[byte_index] ^= bit_mask;
            printf("Casually flipped bit %zu of the ciphertext.\n", flipped_bit);
        } else {
            tag[byte_index - plaintext_length] ^= bit_mask;
            printf("Casually flipped bit %zu of the authentication tag.\n", flipped_bit);
        }
        print_hex("Recieved Tag: ", tag, TAG_LENGTH);
    }

    // Decrypt the ciphertext with AES-GCM or AES-CHAOS-GCM based on the selected chaotic map type and check if the authentication tag is valid.
    if (map_type == NONE) {
        struct AES_GCM_ctx ctx;
        struct AES_GCM_result result = { .buf = ciphertext, .tag = tag };
        AES_GCM_init_ctx(&ctx, key);
        AES_GCM_set_iv(&ctx, iv, IV_LENGTH);
        valid = AES_GCM_authenticated_decrypt_buffer(&ctx, &result, plaintext_length,
                                                     tag, TAG_LENGTH, (uint8_t *)aad, aad_length);
        AES_GCM_free_ctx(&ctx);
    } else {
        struct AES_CHAOS_GCM_ctx ctx;
        struct AES_CHAOS_GCM_result result = { .buf = ciphertext, .tag = tag };
        AES_CHAOS_GCM_init_ctx(&ctx, key, map_type);
        AES_CHAOS_GCM_set_iv(&ctx, iv, IV_LENGTH);
        valid = AES_CHAOS_GCM_authenticated_decrypt_buffer(&ctx, &result,
                                                           plaintext_length, tag, TAG_LENGTH,
                                                           (uint8_t *)aad, aad_length);
        AES_CHAOS_GCM_free_ctx(&ctx);
    }

    if (!valid) {
        printf("ERROR: decryption failed as expected due to the bit flip.\n");
    } else {
        printf("[!] ERROR: decryption succeeded unexpectedly; the bit flip was not detected.\n");
    }

    free(ciphertext);
    return valid ? EXIT_FAILURE : EXIT_SUCCESS;
}
