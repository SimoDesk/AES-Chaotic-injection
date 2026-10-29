#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Args error");
        return 1;
    }

    // known_k2 holds the first 12 bytes of the key that were extracted from the side-channel attack.
    uint8_t known_k1[12];
    hex_to_bytes(argv[1], known_k1, 12);

    // real_master_key holds the full 32-byte AES-256 key that was used for encryption. This key is provided as a command-line argument in hexadecimal format and is used
    // to verify if the brute-force search successfully reconstructs the original key as a quick check after the brute-force phase.
    uint8_t real_master_key[32];
    hex_to_bytes(argv[2], real_master_key, 32);

    // Load the candidate tuples for K1 and K2 from the binary files. Each file contains 256 candidate tuples.
    CandidateTuple col0[256], col1[256], col2[256], col3[256];
    loadCandidates("guesses/col0_candidates.bin", col0);
    loadCandidates("guesses/col1_candidates.bin", col1);
    loadCandidates("guesses/col2_candidates.bin", col2);
    loadCandidates("guesses/col3_candidates.bin", col3);

    // assembled_key will hold the full 32-byte key guess during the brute-force search. It is initialized with the known first 12 bytes of the key.
    uint8_t assembled_key[32];
    memcpy(assembled_key, known_k1, 12);

    // Initialize a counter to keep track of the number of keys tested during the brute-force search.
    long long count = 0;

    // Considering all combinatinons, the brute-force search will test 256^4 = 4,294,967,296 possible keys. 
    // Compared with a full AES-256 brute-force search of 2^256 keys, this is a significantly reduced search space due to the information gained from the side-channel attack.

    // For each guess of K1_12, K2_0, K2_1, K2_2, and K2_3...
    for (int i = 0; i < 256; i++) {
        assembled_key[15] = col0[i].k1;
        assembled_key[16] = col0[i].k2_0; assembled_key[17] = col0[i].k2_1; 
        assembled_key[18] = col0[i].k2_2; assembled_key[19] = col0[i].k2_3;

        // For each guess of K1_13, K2_4, K2_5, K2_6, and K2_7...
        for (int j = 0; j < 256; j++) {
            assembled_key[14] = col1[j].k1;
            assembled_key[20] = col1[j].k2_0; assembled_key[21] = col1[j].k2_1; 
            assembled_key[22] = col1[j].k2_2; assembled_key[23] = col1[j].k2_3;

            // For each guess of K1_14, K2_8, K2_9, K2_10, and K2_11...
            for (int k = 0; k < 256; k++) {
                assembled_key[13] = col2[k].k1;
                assembled_key[24] = col2[k].k2_0; assembled_key[25] = col2[k].k2_1; 
                assembled_key[26] = col2[k].k2_2; assembled_key[27] = col2[k].k2_3;

                // For each guess of K1_15, K2_12, K2_13, K2_14, and K2_15...
                for (int l = 0; l < 256; l++) {
                    assembled_key[12] = col3[l].k1;
                    assembled_key[28] = col3[l].k2_0; assembled_key[29] = col3[l].k2_1; 
                    assembled_key[30] = col3[l].k2_2; assembled_key[31] = col3[l].k2_3;
                    
                    count++;

                    // Check if the assembled key matches the real master key.
                    if (memcmp(assembled_key, real_master_key, 32) == 0) {
                        printf("\n[!!!] MASTER KEY FOUND [!!!]\n");
                        printf("Tested Keys: %lld\n", count);
                        printf("Key: ");

                        for(int z=0; z<32; z++) printf("%02x", assembled_key[z]);
                        printf("\n");

                        return 0; 
                    }
                }
            }
        }
    }

    printf("\nNo key found after testing %lld keys.\n", count);
    return 0;
}