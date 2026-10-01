#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>


#include "aes_default/aes.h"
#include "aes_chaos/aes_chaos.h"
#include "tester.h"

int main(void)
{
    // ==========================================
    // TEST AES-GCM
    // ==========================================
    unsigned int seed = 11122024;
    srand(seed); // Set the initial seed for rand() function

    uint8_t* key = malloc(AES_KEYLEN * sizeof(uint8_t));
    getRandomValue(key, AES_KEYLEN);

    uint8_t* iv = malloc(AES_IVLEN * sizeof(uint8_t));
    getRandomValue(iv, AES_IVLEN);

    uint8_t* text = malloc(TEXT_LENGTH * sizeof(uint8_t));
    getRandomValue(text, TEXT_LENGTH);

    uint8_t* aad = malloc(AAD_LENGTH * sizeof(uint8_t));
    getRandomValue(aad, AAD_LENGTH);
    
    struct stats stCypher, stDecypher;

    FILE *file = fopen("results.csv", "a");
    if (file != NULL) {
        if (ftell(file) == 0) {
            fprintf(file, "Mappa,Fase,Iterazioni,Tempo_s,Energia_uJ,Potenza_W,Memoria_B\n");
        }
        fclose(file);
    }
    
    #ifdef NO_CHAOS
        benchmark(&stCypher, &stDecypher, "AES-GCM standard", text, key, iv, aad);
    #endif

    #ifdef USE_LOGISTIC_MAP
        benchmark_chaos(&stCypher, &stDecypher, "AES-GCM Logistic Map", text, key, iv, aad, LOGISTIC_MAP);
    #endif

    #ifdef USE_TENT_MAP
        benchmark_chaos(&stCypher, &stDecypher, "AES-GCM Tent Map", text, key, iv, aad, TENT_MAP);
    #endif

    #ifdef USE_HENON_MAP
        benchmark_chaos(&stCypher, &stDecypher, "AES-GCM Henon Map", text, key, iv, aad, HENON_MAP);
    #endif

    #ifdef USE_ARNOLD_CAT_MAP
        benchmark_chaos(&stCypher, &stDecypher, "AES-GCM Arnold Cat Map", text, key, iv, aad, ARNOLD_CAT_MAP);
    #endif

    #ifdef USE_SINE_MAP
        benchmark_chaos(&stCypher, &stDecypher, "AES-GCM Sine Map", text, key, iv, aad, SINE_MAP);
    #endif

    free(key);
    free(iv);
    free(text);
    free(aad);
    
    return 0;
}