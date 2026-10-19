/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "aes_chaos.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif

#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/


/*****************************************************************************/
/* Chaos map iterations functions:                                           */

// iterate the logistic map following the equation x_{n+1} = p * x_n * (1 - x_n) and return the difference between the new and old value of x
static double iterateLogisticMap(void* state) {
  struct LogisticMap* map = (struct LogisticMap*) state;

  double x_old = map->x;

  map->x = map->p * map->x * (1 - map->x);

  // Return the difference between the new and old value of x, aka DELTA_W
  return map->x - x_old;
}

// iterate the tent map following the equation x_{n+1} = p * x_n if x_n < 0.5 else p * (1 - x_n) and return the difference between the new and old value of x
static double iterateTentMap(void* state) {
  struct TentMap* map = (struct TentMap*) state;

  double x_old = map->x;

  if (map->x < 0.5) {
    map->x = map->p * map->x;
  } else {
    map->x = map->p * (1 - map->x);
  }

  // Return the difference between the new and old value of x, aka DELTA_W
  return map->x - x_old;
}

// iterate the Henon map following the equations x_{n+1} = 1 - a * x_n^2 + y_n and y_{n+1} = b * x_n and return the difference between the new and old value of x
static double iterateHenonMap(void* state) {
  struct HenonMap* map = (struct HenonMap*) state;

  double x_old = map->x;
  double y_old = map->y;

  map->x = 1 - (map->a * (x_old * x_old)) + y_old;
  map->y = map->b * x_old;

  // Return the difference between the new and old value of x, aka DELTA_W
  return map->x - x_old;
}

// iterate the Arnold Cat Map following the equations x_{n+1} = (x_n + y_n) mod 1 and y_{n+1} = (x_n + 2 * y_n) mod 1 and return the difference between the new and old value of x
static double iterateArnoldCatMap(void* state) {
    struct ArnoldCatMap* map = (struct ArnoldCatMap*) state;

    double x_old = map->x;
    double y_old = map->y;

    // Apply the Arnold Cat Map transformation
    map->x = fmod((x_old + y_old), 1.0);
    map->y = fmod((x_old + 2 * y_old), 1.0);

    // Return the difference between the new and old value of x, aka DELTA_W
    return map->x - x_old;
}

// iterate the Sine Map following the equation x_{n+1} = mu * sin(pi * x_n) and return the difference between the new and old value of x
static double iterateSineMap(void* state) {
    struct SineMap* map = (struct SineMap*) state;

    double x_old = map->x;

    // Apply the Sine Map transformation
    map->x = map->mu * sin(M_PI * x_old);

    // Return the difference between the new and old value of x, aka DELTA_W
    return map->x - x_old;
}

// iterate the Chebyshev Map following the equation x_{n+1} = cos(mu * arccos(x_n)) and return the difference between the new and old value of x
static double iterateChebyshevMap(void* state) {
    struct ChebyshevMap* map = (struct ChebyshevMap*) state;

    double x_old = map->x;

    // Apply the Chebyshev Map transformation
    map->x = cos(map->mu * acos(x_old));

    // Return the difference between the new and old value of x, aka DELTA_W
    return map->x - x_old;
}


// Implementation of the differential equations for the Lorenz, Chen, and Rossler maps
static void iterateDerivatives(ChaosMap map_type, double* state, double* parameters, double* derivatives) {
    switch (map_type) {
        case LORENZ_MAP:
            derivatives[0] = parameters[0] * (state[1] - state[0]); // dx/dt = sigma * (y - x)
            derivatives[1] = state[0] * (parameters[1] - state[2]) - state[1]; // dy/dt = x * (rho - z) - y
            derivatives[2] = (state[0] * state[1]) - (parameters[2] * state[2]); // dz/dt = x * y - beta * z
            break;
        case CHEN_MAP:
            derivatives[0] = parameters[0] * (state[1] - state[0]); // dx/dt = a * (y - x)
            derivatives[1] = (parameters[2] - parameters[0]) * state[0] - state[0] * state[2] + parameters[2] * state[1]; // dy/dt = (c - a) * x - x * z + c * y
            derivatives[2] = state[0] * state[1] - parameters[1] * state[2]; // dz/dt = x * y - b * z
            break;
        case ROSSLER_MAP:
            derivatives[0] = -(state[1] + state[2]); // dx/dt = -y - z
            derivatives[1] = state[0] + parameters[0] * state[1]; // dy/dt = x + a * y
            derivatives[2] = parameters[1] + state[2] * (state[0] - parameters[2]); // dz/dt = b + z * (x - c)
            break;
        default:
            // Handle error: unknown chaos map
            break;
    }
}

// Runge-Kutta 4th order method for iterating the Lorenz, Chen, and Rossler maps by approximating the solution of the differential equations
// with an high degree of accuracy. The function takes the current state, parameters, and time step dt, and updates the state in place.
static void rk4_step(ChaosMap map_type, double* state, double* parameters, double dt) {
    double k1[3], k2[3], k3[3], k4[3];
    double temp_state[3];

    // Calculate k1
    iterateDerivatives(map_type, state, parameters, k1);

    // Calculate k2
    for (int i = 0; i < 3; i++) {
        temp_state[i] = state[i] + 0.5 * dt * k1[i];
    }
    iterateDerivatives(map_type, temp_state, parameters, k2);

    // Calculate k3
    for (int i = 0; i < 3; i++) {
        temp_state[i] = state[i] + 0.5 * dt * k2[i];
    }
    iterateDerivatives(map_type, temp_state, parameters, k3);

    // Calculate k4
    for (int i = 0; i < 3; i++) {
        temp_state[i] = state[i] + dt * k3[i];
    }
    iterateDerivatives(map_type, temp_state, parameters, k4);

    // Update the state using the weighted average of the slopes
    for (int i = 0; i < 3; i++) {
        state[i] += (dt / 6.0) * (k1[i] + 2*k2[i] + 2*k3[i] + k4[i]);
    }
}

// iterate the Lorenz Map using the Runge-Kutta 4th order method and return the difference between the new and old value of x
static double iterateLorenzMap(void* state) {
    struct LorenzMap* map = (struct LorenzMap*) state;
    double x_old = map->x;

    double variables[3] = {map->x, map->y, map->z};
    double parameters[3] = {map->sigma, map->rho, map->beta};

    rk4_step(LORENZ_MAP, variables, parameters, map->dt);

    map->x = variables[0]; 
    map->y = variables[1];
    map->z = variables[2];

    // Return the difference between the new and old value of x, aka DELTA_W
    return map->x - x_old;
}

// iterate the Chen Map using the Runge-Kutta 4th order method and return the difference between the new and old value of x
static double iterateChenMap(void* state) {
    struct ChenMap* map = (struct ChenMap*) state;
    double x_old = map->x;

    double variables[3] = {map->x, map->y, map->z};
    double parameters[3] = {map->a, map->b, map->c};

    rk4_step(CHEN_MAP, variables, parameters, map->dt);

    map->x = variables[0]; 
    map->y = variables[1];
    map->z = variables[2];

    // Return the difference between the new and old value of x, aka DELTA_W
    return map->x - x_old;
}

// iterate the Rossler Map using the Runge-Kutta 4th order method and return the difference between the new and old value of x
static double iterateRosslerMap(void* state) {
    struct RosslerMap* map = (struct RosslerMap*) state;
    double x_old = map->x;

    double variables[3] = {map->x, map->y, map->z};
    double parameters[3] = {map->a, map->b, map->c};

    rk4_step(ROSSLER_MAP, variables, parameters, map->dt);

    map->x = variables[0]; 
    map->y = variables[1];
    map->z = variables[2];

    // Return the difference between the new and old value of x, aka DELTA_W
    return map->x - x_old;
}

/*****************************************************************************/

// Save the seed extracted from the key and IV into the provided hashDigest buffer.
// By doing this instead of using a rand function, I can ensure that the result generating from the seed will be deterministic and reproducible
// regardless of the platform or environment, which is crucial for cryptographic applications where consistency and predictability are required for testing and validation.
static void extractSeedFromKey(struct AES_CHAOS_ctx* ctx, const uint8_t* iv, size_t iv_len, uint8_t hashDigest[32]) {

  // iv_len_bytes is a byte array that will hold the length of the IV in bytes, represented as a 64-bit unsigned integer.
  // This is necessary because the IV length can vary, and we need to include it in the seed extraction process to ensure that different IV lengths produce different seeds.
  uint8_t iv_len_bytes[sizeof(uint64_t)];
  uint64_t iv_len_value = (uint64_t)iv_len;
  if (iv_len > SIZE_MAX - AES_CHAOS_KEYLEN - sizeof(iv_len_bytes)) {
      memset(hashDigest, 0, 32);
      return;
  }

  // The input buffer will hold the concatenation of the original key, the IV length in bytes, and the IV itself.
  size_t input_len = AES_CHAOS_KEYLEN + sizeof(iv_len_bytes) + iv_len;
  uint8_t* input = malloc(input_len);

  // If the input buffer allocation fails, we set the hashDigest to zero and return early to avoid dereferencing a NULL pointer.
  if (input == NULL) {
      memset(hashDigest, 0, 32);
      return;
  }

  // Convert the IV length to a byte array in big-endian order, so that it can be concatenated with the key and IV for hashing.
  for (size_t i = 0; i < sizeof(iv_len_bytes); ++i) {
      iv_len_bytes[sizeof(iv_len_bytes) - 1 - i] = (uint8_t)(iv_len_value >> (i * 8));
  }

  // Concatenate the original key, the IV length in bytes, and the IV itself into the input buffer for hashing.
  memcpy(input, ctx->OriginalKey, AES_CHAOS_KEYLEN);
  memcpy(input + AES_CHAOS_KEYLEN, iv_len_bytes, sizeof(iv_len_bytes));

  // If the IV length is greater than zero, we copy the IV into the input buffer after the key and IV length bytes.
  if (iv_len > 0) {
      memcpy(input + AES_CHAOS_KEYLEN + sizeof(iv_len_bytes), iv, iv_len);
  }

  // Compute the SHA-256 hash of the concatenated input buffer and store the result in hashDigest.
  SHA256(input, input_len, hashDigest);

  free(input);
}

// Extract a normalized seed value from the provided SHA-256 hash digest wich in range (0, 1) and is not exactly 0, 0.5, or 1 to avoid potential issues with certain chaotic maps.
static double extractNormalizedSeedFromHash(const uint8_t* hashDigest) {

  // Use the first 8 bytes of the hash digest to create a 64-bit integer
  uint64_t seedInt = 0;
  for (int i = 0; i < 8; i++) {
      seedInt = (seedInt << 8) | hashDigest[i];
  }

  // Normalize the 64-bit integer to a double in the range (0, 1)
  double seed = (double)seedInt / (double)UINT64_MAX;

  // Ensure the seed is not exactly 0, 0.5, or 1 to avoid potential issues with certain chaotic maps
  if(seed == 0.0 || seed == 0.5 || seed == 1.0) {
      seed += 0.000001;
  }

  return seed;
}

// Update the chaotic state and compute the new value of W_t based on the chaotic map and the parameters alpha, beta, gamma, and delta
static void updateChaos(struct AES_CHAOS_ctx* ctx) {
  double delta_w = 0.0;

  // Update the chaotic state based on the selected chaos map
  switch (ctx->map) {
    case LOGISTIC_MAP:
      delta_w = iterateLogisticMap(ctx->map_state);
      break;
    case TENT_MAP:
      delta_w = iterateTentMap(ctx->map_state);
      break;
    case HENON_MAP:
      delta_w = iterateHenonMap(ctx->map_state);
      break;
    case ARNOLD_CAT_MAP:
      delta_w = iterateArnoldCatMap(ctx->map_state);
      break;
    case SINE_MAP:
      delta_w = iterateSineMap(ctx->map_state);
      break;
    case CHEBYSHEV_MAP:
      delta_w = iterateChebyshevMap(ctx->map_state);
      break;
    case LORENZ_MAP:
      delta_w = iterateLorenzMap(ctx->map_state);
      break;
    case CHEN_MAP:
      delta_w = iterateChenMap(ctx->map_state);
      break;
    case ROSSLER_MAP:
      delta_w = iterateRosslerMap(ctx->map_state);
      break;
    default:
      // Handle error: unknown chaos map
      return;
  }

  // Update W_t based on the chaotic map and the parameters alpha, beta, gamma, and delta.
  // Following the equation W(t+1) = W(t) + alpha * delta_w - beta * |W(t)|
  ctx->W_t = ctx->W_t + (ctx->alpha * delta_w) - (ctx->beta * fabs(ctx->W_t));


  // Compute the chaos modifier using the updated W_t and the parameters gamma and delta, and update the current S-box shift value accordingly.
  double chaos_modifier = ctx->gamma * tanh(ctx->delta * ctx->W_t);
  ctx->current_sbox_shift = (uint8_t)(int)chaos_modifier;
}

// Reset the chaotic state and W_t to their initial values
static void init_chaos(struct AES_CHAOS_ctx* ctx, const uint8_t* iv, size_t iv_len) {
    ctx->W_t = 0.0;

    uint8_t hashDigest[32];
    extractSeedFromKey(ctx, iv, iv_len, hashDigest);

    double extracted_x = extractNormalizedSeedFromHash(hashDigest);
    double extracted_y = extractNormalizedSeedFromHash(hashDigest + 8);
    double extracted_z = extractNormalizedSeedFromHash(hashDigest + 16);

    switch (ctx->map) {
        case LOGISTIC_MAP:
            if (ctx->map_state != NULL) {
                struct LogisticMap* map = (struct LogisticMap*)ctx->map_state;
                map->x = extracted_x; // Reset to the extracted initial value
                map->p = DEFAULT_LOGISTIC_P; // Reset to the default parameter value
            }
            break;
        case TENT_MAP:
            if (ctx->map_state != NULL) {
                struct TentMap* map = (struct TentMap*)ctx->map_state;
                map->x = extracted_x; // Reset to the extracted initial value
                map->p = DEFAULT_TENT_P; // Reset to the default parameter value
            }
            break;
        case HENON_MAP:
            if (ctx->map_state != NULL) {
                struct HenonMap* map = (struct HenonMap*)ctx->map_state;
                map->x = extracted_x - 0.5; // Reset to the extracted initial value, shifted to be centered around 0
                map->y = extracted_y - 0.5; // Reset to the extracted initial value, shifted to be centered around 0
                map->a = DEFAULT_HENON_A; // Reset to the default parameter value 
                map->b = DEFAULT_HENON_B; // Reset to the default parameter value
            }
            break;
        case ARNOLD_CAT_MAP:
            if (ctx->map_state != NULL) {
                struct ArnoldCatMap* map = (struct ArnoldCatMap*)ctx->map_state;
                map->x = extracted_x; // Reset to the extracted initial value
                map->y = extracted_y; // Reset to the extracted initial value
            }
            break;
        case SINE_MAP:
            if (ctx->map_state != NULL) {
                struct SineMap* map = (struct SineMap*)ctx->map_state;
                map->x = extracted_x; // Reset to the extracted initial value
                map->mu = DEFAULT_SINE_MU; // Reset to the default parameter value
            }
            break;
        case CHEBYSHEV_MAP:
            if (ctx->map_state != NULL) {
                struct ChebyshevMap* map = (struct ChebyshevMap*)ctx->map_state;
                map->x = (extracted_x * 2.0) - 1.0; // Reset to the extracted initial value, scaled to be in the range [-1, 1]
                map->mu = DEFAULT_CHEBYSHEV_MU; // Reset to the default parameter value
            }
            break;
        case LORENZ_MAP:
            if (ctx->map_state != NULL) {
                struct LorenzMap* map = (struct LorenzMap*)ctx->map_state;
                map->x = 0.1 + (extracted_x * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->y = 0.1 + (extracted_y * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->z = 0.1 + (extracted_z * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->sigma = DEFAULT_LORENZ_SIGMA; // Reset to the default parameter value
                map->rho = DEFAULT_LORENZ_RHO; // Reset to the default parameter value
                map->beta = DEFAULT_LORENZ_BETA; // Reset to the default parameter value

                map->dt = DEFAULT_DT; // Reset to the default time step value
            }
            break;
        case CHEN_MAP:
            if (ctx->map_state != NULL) {
                struct ChenMap* map = (struct ChenMap*)ctx->map_state;
                map->x = 0.1 + (extracted_x * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->y = 0.1 + (extracted_y * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->z = 0.1 + (extracted_z * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->a = DEFAULT_CHEN_A; // Reset to the default parameter value
                map->b = DEFAULT_CHEN_B; // Reset to the default parameter value
                map->c = DEFAULT_CHEN_C; // Reset to the default parameter value

                map->dt = DEFAULT_DT; // Reset to the default time step value
            }
            break;
        case ROSSLER_MAP:
            if (ctx->map_state != NULL) {
                struct RosslerMap* map = (struct RosslerMap*)ctx->map_state;
                map->x = 0.1 + (extracted_x * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->y = 0.1 + (extracted_y * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->z = 0.1 + (extracted_z * 0.1); // Reset to the extracted initial value, scaled to be in the range [0.1, 0.2]
                map->a = DEFAULT_ROSSLER_A; // Reset to the default parameter value
                map->b = DEFAULT_ROSSLER_B; // Reset to the default parameter value
                map->c = DEFAULT_ROSSLER_C; // Reset to the default parameter value

                map->dt = DEFAULT_DT; // Reset to the default time step value
            }
            break;
        default:
            // Handle error: unknown chaos map
            break;
    }

    // Number of iterations to perform before starting the encryption/decryption process,
    // this is to ensure that the chaotic system has reached a sufficiently chaotic state and is not in a transient phase.
    int pre_iterations = 500; 

    
    // For the Lorenz, Chen, and Rossler maps, we can reduce the number of pre-iterations since they are continuous-time systems,
    // doing too many iterations may lead to numerical instability or overflow issues, so we limit the number of pre-iterations to 10 for these maps.
    if (ctx->map == LORENZ_MAP || ctx->map == CHEN_MAP || ctx->map == ROSSLER_MAP) {
        pre_iterations = 10; 
    }
    

    // Perform the pre-iterations to allow the chaotic system to reach a sufficiently chaotic state
    for (int i = 0; i < pre_iterations; i++) {
        updateChaos(ctx);
    }
}

// Compute the chaotic S-box value based on the current chaotic state and the input byte x
static uint8_t getChaoticSBoxValue_update(struct AES_CHAOS_ctx* ctx, uint8_t x) {
  // First, move forward the chaotic state and compute the new value of W_t
  updateChaos(ctx);

  // By using the standard construction of the S-Box, which is based on the multiplicative inverse in GF(2^8) followed by an affine transformation,
  // I can use it to calculate A * x^-1 (XOR) C without the need to compute the multiplicative inverse, which is a costly operation.
  // Then, I can use the current_sbox_shift value to perturb the S-box value, which corresponds to the chaotic perturbation: gamma * tanh(delta * W(t)).
  // Combined together, the formula is A * x^-1 (XOR) C + gamma * tanh(delta * W(t)) wich is what alters the S-box value based on the chaotic state.
  return (uint8_t) (sbox[x] + ctx->current_sbox_shift);
}

// Compute the chaotic S-box value based on the current chaotic state and the input byte x without updating the chaotic state
static uint8_t getChaoticSBoxValue_static(struct AES_CHAOS_ctx* ctx, uint8_t x) {
  return (uint8_t) (sbox[x] + ctx->current_sbox_shift);
}

static void KeyExpansion(struct AES_CHAOS_ctx* ctx, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  for (i = 0; i < Nk; ++i)
  {
    ctx->RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    ctx->RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    ctx->RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    ctx->RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=ctx->RoundKey[k + 0];
      tempa[1]=ctx->RoundKey[k + 1];
      tempa[2]=ctx->RoundKey[k + 2];
      tempa[3]=ctx->RoundKey[k + 3];
    }

    if (i % Nk == 0)
    {
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      {
        tempa[0] = getChaoticSBoxValue_update(ctx, tempa[0]);
        tempa[1] = getChaoticSBoxValue_update(ctx, tempa[1]);
        tempa[2] = getChaoticSBoxValue_update(ctx, tempa[2]);
        tempa[3] = getChaoticSBoxValue_update(ctx, tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      {
        tempa[0] = getChaoticSBoxValue_update(ctx, tempa[0]);
        tempa[1] = getChaoticSBoxValue_update(ctx, tempa[1]);
        tempa[2] = getChaoticSBoxValue_update(ctx, tempa[2]);
        tempa[3] = getChaoticSBoxValue_update(ctx, tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    ctx->RoundKey[j + 0] = ctx->RoundKey[k + 0] ^ tempa[0];
    ctx->RoundKey[j + 1] = ctx->RoundKey[k + 1] ^ tempa[1];
    ctx->RoundKey[j + 2] = ctx->RoundKey[k + 2] ^ tempa[2];
    ctx->RoundKey[j + 3] = ctx->RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_CHAOS_init_ctx(struct AES_CHAOS_ctx* ctx, const uint8_t* key, ChaosMap map_type)
{
  ctx->map = map_type;
  memcpy(ctx->OriginalKey, key, AES_CHAOS_KEYLEN);
  ctx->W_t = 0.0;
  ctx->gamma = DEFAULT_GAMMA;
  ctx->delta = DEFAULT_DELTA;

  ctx->current_sbox_shift = 0;

  switch (map_type) {
    case LOGISTIC_MAP:
      ctx->map_state = malloc(sizeof(struct LogisticMap));
      ctx->alpha = DEFAULT_CHAOS_LOGISTIC_ALPHA;
      ctx->beta = DEFAULT_CHAOS_LOGISTIC_BETA;
      break;
    case TENT_MAP:
      ctx->map_state = malloc(sizeof(struct TentMap));
      ctx->alpha = DEFAULT_CHAOS_TENT_ALPHA;
      ctx->beta = DEFAULT_CHAOS_TENT_BETA;
      break;
    case HENON_MAP:
      ctx->map_state = malloc(sizeof(struct HenonMap));
      ctx->alpha = DEFAULT_CHAOS_HENON_ALPHA;
      ctx->beta = DEFAULT_CHAOS_HENON_BETA;
      break;
    case ARNOLD_CAT_MAP:
      ctx->map_state = malloc(sizeof(struct ArnoldCatMap));
      ctx->alpha = DEFAULT_CHAOS_ARNOLD_ALPHA;
      ctx->beta = DEFAULT_CHAOS_ARNOLD_BETA;
      break;
    case SINE_MAP:
      ctx->map_state = malloc(sizeof(struct SineMap));
      ctx->alpha = DEFAULT_CHAOS_SINE_ALPHA;
      ctx->beta = DEFAULT_CHAOS_SINE_BETA;
      break;
    case CHEBYSHEV_MAP:
      ctx->map_state = malloc(sizeof(struct ChebyshevMap));
      ctx->alpha = DEFAULT_CHAOS_CHEBYSHEV_ALPHA;
      ctx->beta = DEFAULT_CHAOS_CHEBYSHEV_BETA;
      break;
    case LORENZ_MAP:
      ctx->map_state = malloc(sizeof(struct LorenzMap));
      ctx->alpha = DEFAULT_CHAOS_LORENZ_ALPHA;
      ctx->beta = DEFAULT_CHAOS_LORENZ_BETA;
      break;
    case CHEN_MAP:
      ctx->map_state = malloc(sizeof(struct ChenMap));
      ctx->alpha = DEFAULT_CHAOS_CHEN_ALPHA;
      ctx->beta = DEFAULT_CHAOS_CHEN_BETA;
      break;
    case ROSSLER_MAP:
      ctx->map_state = malloc(sizeof(struct RosslerMap));
      ctx->alpha = DEFAULT_CHAOS_ROSSLER_ALPHA;
      ctx->beta = DEFAULT_CHAOS_ROSSLER_BETA;
      break;
    default:
      ctx->map_state = NULL;
      break;
  }

  init_chaos(ctx, NULL, 0);
  KeyExpansion(ctx, key);
}

// Set the parameters alpha and beta for the chaotic map in the AES_CHAOS context. These parameters control the influence of the chaotic map on the encryption process.
void AES_CHAOS_ctx_set_params(struct AES_CHAOS_ctx* ctx, double alfa, double beta) {
  ctx->alpha = alfa;
  ctx->beta = beta;
}

// Set the iv and iv_len for the AES_CHAOS_GCM context.
int AES_CHAOS_GCM_set_iv(struct AES_CHAOS_GCM_ctx* ctx, const uint8_t* iv, size_t iv_len) {

  // Allocate memory for the new IV and copy the provided IV into it. If iv_len is greater than 0, we need to allocate memory for the new IV.
  uint8_t* new_iv = NULL;

  // Check for invalid input: if ctx is NULL or if iv_len is greater than 0 but iv is NULL, return 0 to indicate failure.
  if (ctx == NULL || (iv_len > 0 && iv == NULL)) {
    return 0;
  }

  // If iv_len is greater than 0, allocate memory for the new IV and copy the provided IV into it. If memory allocation fails, return 0 to indicate failure.
  if (iv_len > 0) {
    new_iv = malloc(iv_len);
    if (new_iv == NULL) {
      return 0;
    }
    memcpy(new_iv, iv, iv_len);
  }

  // Free the old IV if it exists to avoid memory leaks.
  free(ctx->Iv);

  // Update the context with the new IV and its length.
  ctx->Iv = new_iv;
  ctx->IvLen = iv_len;

  init_chaos(&ctx->aes, ctx->Iv, ctx->IvLen);

  KeyExpansion(&ctx->aes, ctx->aes.OriginalKey);

  return 1;
}

// Initialize the AES_CHAOS_GCM context with the provided key and chaotic map type. The IV is set to NULL and its length to 0.
void AES_CHAOS_GCM_init_ctx(struct AES_CHAOS_GCM_ctx* ctx, const uint8_t* key, ChaosMap map_type) {
  ctx->Iv = NULL;
  ctx->IvLen = 0;
  AES_CHAOS_init_ctx(&ctx->aes, key, map_type);
}

// Free the memory allocated for the chaotic map state in the AES_CHAOS context. 
void AES_CHAOS_free_ctx(struct AES_CHAOS_ctx* ctx) {
  if (ctx != NULL) {
    free(ctx->map_state);

    ctx->map_state = NULL;
  }
}

// Free the memory allocated for the IV in the AES_CHAOS_GCM context and free the AES_CHAOS context.
void AES_CHAOS_GCM_free_ctx(struct AES_CHAOS_GCM_ctx* ctx) {
  if (ctx != NULL) {
    free(ctx->Iv);
    ctx->Iv = NULL;
    ctx->IvLen = 0;
    AES_CHAOS_free_ctx(&ctx->aes);
  }
}

static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

static void SubBytes(struct AES_CHAOS_ctx* ctx, state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getChaoticSBoxValue_static(ctx, (*state)[j][i]);
    }
  }
}

static void ShiftRows(state_t* state)
{
  uint8_t temp;

  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// Cipher function that performs the AES encryption process using the chaotic S-box and other transformations
static void Cipher(struct AES_CHAOS_ctx* ctx, state_t* state, const uint8_t* RoundKey)
{
  updateChaos(ctx);

  uint8_t round = 0;

  AddRoundKey(0, state, RoundKey);

  for (round = 1; ; ++round)
  {
    // updateChaos(ctx);

    SubBytes(ctx, state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  AddRoundKey(Nr, state, RoundKey);
}

size_t AES_CHAOS_get_heap_size(ChaosMap map_type) {
    switch (map_type) {
        case LOGISTIC_MAP:
            return sizeof(struct LogisticMap);
        case TENT_MAP:
            return sizeof(struct TentMap);
        case HENON_MAP:
            return sizeof(struct HenonMap);
        case ARNOLD_CAT_MAP:
            return sizeof(struct ArnoldCatMap);
        case SINE_MAP:
            return sizeof(struct SineMap);
        case CHEBYSHEV_MAP:
            return sizeof(struct ChebyshevMap);
        case LORENZ_MAP:
            return sizeof(struct LorenzMap);
        case CHEN_MAP:
            return sizeof(struct ChenMap);
        case ROSSLER_MAP:
            return sizeof(struct RosslerMap);
        default:
            return 0; // Unknown map type
    }
}

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

void AES_CHAOS_ECB_encrypt(struct AES_CHAOS_ctx* ctx, uint8_t* buf)
{
  Cipher(ctx, (state_t*)buf, ctx->RoundKey);
}

// Galois multiplication in GF(2^128) for GCM mode
void AES_CHAOS_galoisMoltiplication(const uint8_t *X, const uint8_t *Y, uint8_t *result) {
  uint8_t Z[AES_CHAOS_BLOCKLEN] = {0};

  uint8_t V[AES_CHAOS_BLOCKLEN];
  memcpy(V, Y, AES_CHAOS_BLOCKLEN);

  for(int i = 0; i < (AES_CHAOS_BLOCKLEN*8); i++) {
    int byte_idx = i / 8;
    int bit_idx = 7 - (i % 8);
    uint8_t x_i = (X[byte_idx] >> bit_idx) & 1;

    uint8_t x_i_mask = (uint8_t)(-x_i);

    for (int k = 0; k < AES_CHAOS_BLOCKLEN; k++) {
      Z[k] ^= (V[k] & x_i_mask); 
    }

    int doXor = V[AES_CHAOS_BLOCKLEN - 1] & 1;

    int curr_carry = 0;
    for(int j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
      int next_carry = V[j] & 1;
      V[j] >>= 1;
      V[j] |= (curr_carry << 7);
      curr_carry = next_carry;
    }

    uint8_t doXor_mask = (uint8_t)(-doXor);
    V[0] ^= (0xe1 & doXor_mask);     
  }

  memcpy(result, Z, AES_CHAOS_BLOCKLEN);
}

static void counterInc32(uint8_t* counter) {
  for (int i = AES_CHAOS_BLOCKLEN - 1; i >= AES_CHAOS_BLOCKLEN - 4; --i) {
    if (counter[i] == 255) {
      counter[i] = 0;
    } else {
      counter[i]++;
      break;
    }
  }
}

static void AES_CHAOS_GCM_xcrypt_buffer(struct AES_CHAOS_GCM_ctx* ctx, uint8_t* counter, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_CHAOS_BLOCKLEN];
  
  size_t i;
  int bi;
  for (i = 0, bi = AES_CHAOS_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_CHAOS_BLOCKLEN)
    {
      memcpy(buffer, counter, AES_CHAOS_BLOCKLEN);
      Cipher(&ctx->aes, (state_t*)buffer, ctx->aes.RoundKey);

      for (bi = (AES_CHAOS_BLOCKLEN - 1); bi >= (AES_CHAOS_BLOCKLEN - 4); --bi)
      {
        if (counter[bi] == 255)
	      {
          counter[bi] = 0;
          continue;
        } 
        counter[bi] += 1;
        break;   
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

void AES_CHAOS_GCM_authenticated_encrypt_buffer(struct AES_CHAOS_GCM_ctx* ctx, struct AES_CHAOS_GCM_result* res, size_t length, uint8_t* aad, size_t aad_length, size_t tag_length) {
  const uint8_t* iv = ctx != NULL ? ctx->Iv : NULL;
  size_t iv_len = ctx != NULL ? ctx->IvLen : 0;
  if (ctx == NULL || res == NULL || res->buf == NULL || res->tag == NULL ||
      (iv_len > 0 && iv == NULL) ||
      tag_length == 0 || tag_length > AES_CHAOS_GCM_TAGLEN) {
    return;
  }

  uint8_t H[AES_CHAOS_BLOCKLEN] = {0};
  Cipher(&ctx->aes, (state_t*)H, ctx->aes.RoundKey);
  
  uint8_t J[AES_CHAOS_BLOCKLEN] = {0};
  if(iv_len == 12) {
    memcpy(J, iv, 12);
    J[12] = 0x00;
    J[13] = 0x00;
    J[14] = 0x00;
    J[15] = 0x01;
  } else {
    for (size_t i = 0; i < iv_len; i += AES_CHAOS_BLOCKLEN) {
      for (size_t j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
        if (i + j < iv_len)
          J[j] ^= iv[i + j];
      }
      AES_CHAOS_galoisMoltiplication(J, H, J); 
    }    

    uint8_t iv_len_block[AES_CHAOS_BLOCKLEN] = {0};
    uint64_t iv_bits = (uint64_t)iv_len * 8;
    
    iv_len_block[8]  = (iv_bits >> 56) & 0xFF;
    iv_len_block[9]  = (iv_bits >> 48) & 0xFF;
    iv_len_block[10] = (iv_bits >> 40) & 0xFF;
    iv_len_block[11] = (iv_bits >> 32) & 0xFF;
    iv_len_block[12] = (iv_bits >> 24) & 0xFF;
    iv_len_block[13] = (iv_bits >> 16) & 0xFF;
    iv_len_block[14] = (iv_bits >> 8) & 0xFF;
    iv_len_block[15] = (iv_bits) & 0xFF;

    for (int j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
      J[j] ^= iv_len_block[j];
    }
    AES_CHAOS_galoisMoltiplication(J, H, J);
  }

  uint8_t Jinc[AES_CHAOS_BLOCKLEN];
  memcpy(Jinc, J, AES_CHAOS_BLOCKLEN);
  counterInc32(Jinc); 

  AES_CHAOS_GCM_xcrypt_buffer(ctx, Jinc, res->buf, length);

  uint8_t S[AES_CHAOS_BLOCKLEN] = {0};

  for (size_t i = 0; i < aad_length; i += AES_CHAOS_BLOCKLEN) {
    for (size_t j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
      if (i + j < aad_length)
        S[j] ^= aad[i + j];
    }
    AES_CHAOS_galoisMoltiplication(S, H, S);
  }

  for (size_t i = 0; i < length; i += AES_CHAOS_BLOCKLEN) {
    for (size_t j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
      if (i + j < length)
        S[j] ^= res->buf[i + j];
    }
    AES_CHAOS_galoisMoltiplication(S, H, S);
  }

  uint8_t len_block[AES_CHAOS_BLOCKLEN] = {0};
  uint64_t len_aad_bits = (uint64_t)aad_length * 8;
  uint64_t len_buf_bits = (uint64_t)length * 8;

  len_block[0] = (len_aad_bits >> 56) & 0xFF;
  len_block[1] = (len_aad_bits >> 48) & 0xFF;
  len_block[2] = (len_aad_bits >> 40) & 0xFF;
  len_block[3] = (len_aad_bits >> 32) & 0xFF;
  len_block[4] = (len_aad_bits >> 24) & 0xFF;
  len_block[5] = (len_aad_bits >> 16) & 0xFF;
  len_block[6] = (len_aad_bits >> 8) & 0xFF;
  len_block[7] = (len_aad_bits) & 0xFF;
  len_block[8] = (len_buf_bits >> 56) & 0xFF;
  len_block[9] = (len_buf_bits >> 48) & 0xFF;
  len_block[10]= (len_buf_bits >> 40) & 0xFF;
  len_block[11]= (len_buf_bits >> 32) & 0xFF;
  len_block[12]= (len_buf_bits >> 24) & 0xFF;
  len_block[13]= (len_buf_bits >> 16) & 0xFF;
  len_block[14]= (len_buf_bits >> 8) & 0xFF;
  len_block[15]= (len_buf_bits) & 0xFF;

  for (int j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
    S[j] ^= len_block[j];
  }
  AES_CHAOS_galoisMoltiplication(S, H, S);

  uint8_t Jtag[AES_CHAOS_BLOCKLEN];
  memcpy(Jtag, J, AES_CHAOS_BLOCKLEN);
  AES_CHAOS_GCM_xcrypt_buffer(ctx, Jtag, S, AES_CHAOS_BLOCKLEN);

  memcpy(res->tag, S, tag_length);
}

int AES_CHAOS_GCM_authenticated_decrypt_buffer(struct AES_CHAOS_GCM_ctx* ctx, struct AES_CHAOS_GCM_result* res, size_t length, const uint8_t* tag, size_t tag_length, uint8_t* aad, size_t aad_length) {
  const uint8_t* iv = ctx != NULL ? ctx->Iv : NULL;
  size_t iv_len = ctx != NULL ? ctx->IvLen : 0;
  if (ctx == NULL || res == NULL || res->buf == NULL ||
      (iv_len > 0 && iv == NULL) || tag == NULL ||
      tag_length == 0 || tag_length > AES_CHAOS_GCM_TAGLEN) {
    return 0;
  }
  
  uint8_t H[AES_CHAOS_BLOCKLEN] = {0};
  Cipher(&ctx->aes, (state_t*)H, ctx->aes.RoundKey);

  uint8_t J[AES_CHAOS_BLOCKLEN] = {0};
  if(iv_len == 12) {
    memcpy(J, iv, 12);
    J[12] = 0x00; J[13] = 0x00; J[14] = 0x00; J[15] = 0x01;
  } else {
    for (size_t i = 0; i < iv_len; i += AES_CHAOS_BLOCKLEN) {
      for (size_t j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
        if (i + j < iv_len)
          J[j] ^= iv[i + j];
      }
      AES_CHAOS_galoisMoltiplication(J, H, J); 
    }    

    uint8_t iv_len_block[AES_CHAOS_BLOCKLEN] = {0};
    uint64_t iv_bits = (uint64_t)iv_len * 8;
    
    iv_len_block[8]  = (iv_bits >> 56) & 0xFF;
    iv_len_block[9]  = (iv_bits >> 48) & 0xFF;
    iv_len_block[10] = (iv_bits >> 40) & 0xFF;
    iv_len_block[11] = (iv_bits >> 32) & 0xFF;
    iv_len_block[12] = (iv_bits >> 24) & 0xFF;
    iv_len_block[13] = (iv_bits >> 16) & 0xFF;
    iv_len_block[14] = (iv_bits >> 8) & 0xFF;
    iv_len_block[15] = (iv_bits) & 0xFF;

    for (int j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
      J[j] ^= iv_len_block[j];
    }
    AES_CHAOS_galoisMoltiplication(J, H, J);
  }

  uint8_t S[AES_CHAOS_BLOCKLEN] = {0};

  for (size_t i = 0; i < aad_length; i += AES_CHAOS_BLOCKLEN) {
    for (size_t j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
      if (i + j < aad_length)
        S[j] ^= aad[i + j];
    }
    AES_CHAOS_galoisMoltiplication(S, H, S);
  }

  for (size_t i = 0; i < length; i += AES_CHAOS_BLOCKLEN) {
    for (size_t j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
      if (i + j < length)
        S[j] ^= res->buf[i + j];
    }
    AES_CHAOS_galoisMoltiplication(S, H, S);
  }

  uint8_t len_block[AES_CHAOS_BLOCKLEN] = {0};
  uint64_t len_aad_bits = (uint64_t)aad_length * 8;
  uint64_t len_buf_bits = (uint64_t)length * 8;

  len_block[0] = (len_aad_bits >> 56) & 0xFF; len_block[1] = (len_aad_bits >> 48) & 0xFF;
  len_block[2] = (len_aad_bits >> 40) & 0xFF; len_block[3] = (len_aad_bits >> 32) & 0xFF;
  len_block[4] = (len_aad_bits >> 24) & 0xFF; len_block[5] = (len_aad_bits >> 16) & 0xFF;
  len_block[6] = (len_aad_bits >> 8) & 0xFF;  len_block[7] = (len_aad_bits) & 0xFF;
  len_block[8] = (len_buf_bits >> 56) & 0xFF; len_block[9] = (len_buf_bits >> 48) & 0xFF;
  len_block[10]= (len_buf_bits >> 40) & 0xFF; len_block[11]= (len_buf_bits >> 32) & 0xFF;
  len_block[12]= (len_buf_bits >> 24) & 0xFF; len_block[13]= (len_buf_bits >> 16) & 0xFF;
  len_block[14]= (len_buf_bits >> 8) & 0xFF;  len_block[15]= (len_buf_bits) & 0xFF;

  for (int j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
    S[j] ^= len_block[j];
  }
  AES_CHAOS_galoisMoltiplication(S, H, S);

  uint8_t Jinc[AES_CHAOS_BLOCKLEN];
  memcpy(Jinc, J, AES_CHAOS_BLOCKLEN);
  counterInc32(Jinc); 

  AES_CHAOS_GCM_xcrypt_buffer(ctx, Jinc, res->buf, length);

  // In the chaotic imlpementation of the decryption, the tag is computed after the decryption of the ciphertext, because the chaotic state is updated during the decryption process.
  // This means that the tag is computed based on the decrypted plaintext, which is consistent with the GCM specification.
  // The tag is then compared to the provided tag to verify the authenticity of the message.
  AES_CHAOS_GCM_xcrypt_buffer(ctx, J, S, AES_CHAOS_BLOCKLEN);

  uint8_t diff = 0;
  for (size_t i = 0; i < tag_length; i++) {
    diff |= (S[i] ^ tag[i]);
  }
  
  if (diff != 0) {
    return 0;
  }

  return 1;
}