#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


#include "aes_default/aes.h"
#include "tester.h"

int main(void)
{
    // ==========================================
    // TEST AES-GCM
    // ==========================================
    unsigned int seed = 11122024;
    srand(seed); // Set the initial seed for rand() function

    uint8_t* key = malloc(32 * sizeof(uint8_t));
    getRandomValue(key, 32);

    uint8_t* iv = malloc(16 * sizeof(uint8_t));
    getRandomValue(iv, 16);

    uint8_t* text = malloc(TEXT_LENGTH * sizeof(uint8_t));
    getRandomValue(text, TEXT_LENGTH);

    uint8_t* aad = malloc(AAD_LENGTH * sizeof(uint8_t));
    getRandomValue(aad, AAD_LENGTH);
    
    struct stats stCypher, stDecypher;
    
    banchmark(&stCypher, &stDecypher, "AES-GCM standard", AES_GCM_authenticated_encrypt_buffer, AES_GCM_authenticated_decrypt_buffer, text, key, iv, aad);

/*
    // Attack Simulation: Alteration of a byte in the ciphertext
    printf("Simulazione attacco: alterazione di un byte del testo cifrato...\n");
    
    memcpy(buffer.buf, text, TEXT_LENGTH);
    
    AES_init_ctx_iv(&ctx_gcm, key, iv);
    AES_GCM_authenticated_encrypt_buffer(&ctx_gcm, &buffer, TEXT_LENGTH, 12, aad, AAD_LENGTH);
    
    // Randomly alter a byte in the ciphertext to simulate tampering
    buffer.buf[5] ^= 0xFF; 

    AES_init_ctx_iv(&ctx_gcm, key, iv);
    is_valid = AES_GCM_authenticated_decrypt_buffer(&ctx_gcm, &buffer, buffer.tag, TEXT_LENGTH, 12, aad, AAD_LENGTH);

    if (is_valid) {
        printf("[ERRORE CRITICO] Il tag manomesso è stato accettato!\n");
    } else {
        printf("[SUCCESS] Sicurezza attiva: pacchetto manomesso scartato correttamente.\n");
    }
*/

    free(key);
    free(iv);
    free(text);
    free(aad);
    
    return 0;
}