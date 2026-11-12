#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

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

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s map alpha beta\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Define a fixed key for AES-CHAOS
    const uint8_t key[AES_CHAOS_KEYLEN] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };

    // Parse alpha and beta from the command line arguments
    char* end = NULL;
    double alpha = strtod(argv[2], &end);
    if (*end != '\0') {
        return EXIT_FAILURE;
    }
    double beta = strtod(argv[3], &end);
    if (*end != '\0') {
        return EXIT_FAILURE;
    }

    // Parse the chaos map type from the command line argument
    ChaosMap map_type = parseMapType(argv[1]);

    double min_w;
    double max_w;

    // saturated variable to count how many times the chaotic variable W(t) exceeds the saturation threshold
    size_t saturated;

    // non_finite variable to count how many times the chaotic variable W(t) becomes non-finite (NaN or Inf)
    size_t non_finite;

    // First, measure the stability with delta = 0.0 to get the min and max values of W(t)
    if (!AES_CHAOS_measure_stability(map_type, key, alpha, beta, 0.0, 100, &min_w, &max_w, &saturated, &non_finite)) {
        return EXIT_FAILURE;
    }

    // w_max is the maximum absolute value of W(t) observed during the stability measurement
    double w_max = fmax(fabs(min_w), fabs(max_w));

    // Calculate delta based on the maximum absolute value of W(t) to keep delta * W(t) within the non-saturated range of tanh
    double delta = w_max > 0.0 ? 2.0 / w_max : 0.0;

    // Now, measure the stability with the calculated delta
    if (!AES_CHAOS_measure_stability(map_type, key, alpha, beta, delta, 100, &min_w, &max_w, &saturated, &non_finite)) {
        return EXIT_FAILURE;
    }

    // Print the results in CSV format: min_w, max_w, w_max, delta, saturated_count, non_finite_count
    printf("%.17g,%.17g,%.17g,%.17g,%zu,%zu\n", min_w, max_w, w_max, delta, saturated, non_finite);

}
