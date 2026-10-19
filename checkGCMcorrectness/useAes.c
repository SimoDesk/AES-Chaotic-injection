#include <stdlib.h>
#include <stdio.h>

#include "../aes_default/aes.h"

// Function to convert a hexadecimal string to a byte array
void hex_to_bytes(const char* hex_str, uint8_t* byte_array, size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; i++) {
        sscanf(hex_str + 2*i, "%2hhx", &byte_array[i]);
    }
}

int main(int argc, char *argv[])
{

    // First, check if the correct number of arguments is provided. 
    // The program expects 12 arguments: operation type, key length, IV length, plaintext length, AAD length, tag length, key in hex, 
    // IV in hex, plaintext in hex, AAD in hex, ciphertext in hex, and tag in hex.

    if (argc < 13) {
        printf("Args error");
        return EXIT_FAILURE;
    }

    char operation = argv[1][0]; // 'e' for encryption, 'd' for decryption
    
    int key_len = atoi(argv[2]);
    int iv_len = atoi(argv[3]);
    int pt_len = atoi(argv[4]);
    int aad_len = atoi(argv[5]);
    int tag_len = atoi(argv[6]);

    uint8_t key[key_len];
    uint8_t iv[iv_len];
    uint8_t plainText[pt_len];
    uint8_t aad[aad_len];
    uint8_t cipherText[pt_len];
    uint8_t tag[tag_len];
    
    hex_to_bytes(argv[7], key, key_len);
    hex_to_bytes(argv[8], iv, iv_len);
    hex_to_bytes(argv[9], plainText, pt_len);
    hex_to_bytes(argv[10], aad, aad_len);
    hex_to_bytes(argv[11], cipherText, pt_len);
    hex_to_bytes(argv[12], tag, tag_len);

    struct AES_GCM_result res;
    res.tag = tag;

    struct AES_GCM_ctx ctx;
    AES_GCM_init_ctx(&ctx, key);
    if (!AES_GCM_set_iv(&ctx, iv, iv_len)) return EXIT_FAILURE;

    // Depending on the operation type, either encrypt or decrypt the data.
    if (operation == 'e') {
        res.buf = plainText;
        AES_GCM_authenticated_encrypt_buffer(&ctx, &res, pt_len, aad, aad_len, tag_len);
        
        printf("Ciphertext: ");
        for (int i = 0; i < pt_len; i++) printf("%02x", res.buf[i]);
        printf("\nTag: ");
        for (int i = 0; i < tag_len; i++) printf("%02x", res.tag[i]);
        printf("\n");
        
    } else if (operation == 'd') {        res.buf = cipherText;
        int decrypt_result = AES_GCM_authenticated_decrypt_buffer(&ctx, &res, pt_len, tag, tag_len, aad, aad_len);
        
        if (decrypt_result == 1) {
            printf("Decryption successful. Plaintext: ");
            for (int i = 0; i < pt_len; i++) printf("%02x", res.buf[i]);
            printf("\n");
        } else {
            printf("Decryption failed. Authentication tag mismatch.\n");
        }
    }

    AES_GCM_free_ctx(&ctx);
    return 0;
}