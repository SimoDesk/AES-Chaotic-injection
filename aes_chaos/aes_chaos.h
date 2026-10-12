#ifndef _AES_CHAOS_H_
#define _AES_CHAOS_H_

#include <stdint.h>
#include <stddef.h>

#define AES256 1

#define AES_CHAOS_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define AES_CHAOS_GCM_TAGLEN 16 // Tag length in bytes - GCM is 128b tag only

#if defined(AES256) && (AES256 == 1)
    #define AES_CHAOS_KEYLEN 32
    #define AES_CHAOS_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_CHAOS_KEYLEN 24
    #define AES_CHAOS_keyExpSize 208
#else
    #define AES_CHAOS_KEYLEN 16   // Key length in bytes
    #define AES_CHAOS_keyExpSize 176
#endif

// Define default parameters for the chaotic implementation.
#define DEFAULT_APLHA 0.050
#define DEFAULT_BETA 0.001
#define DEFAULT_GAMMA 255
#define DEFAULT_DELTA 1

// Define the chaotic map types.
typedef enum {
  NONE,
  LOGISTIC_MAP,
  TENT_MAP,
  HENON_MAP,
  ARNOLD_CAT_MAP,
  SINE_MAP,
  CHEBYSHEV_MAP,
  LORENZ_MAP,
  CHEN_MAP,
  ROSSLER_MAP,
} ChaosMap;

// Define the structures for the logistic map and its default parameters.
struct LogisticMap {
  double x;
  double p;
};
#define DEFAULT_LOGISTIC_P 3.75
#define DEFAULT_LOGISTIC_X 0.5

// Define the structures for the tent map and its default parameters.
struct TentMap {
  double x;
  double p;
};
#define DEFAULT_TENT_P 1.9998;
#define DEFAULT_TENT_X 0.123;

// Define the structures for the Henon map and its default parameters.
struct HenonMap {
  double x, y;
  double a, b;
};
#define DEFAULT_HENON_A 1.4
#define DEFAULT_HENON_B 0.3
#define DEFAULT_HENON_X 0.1
#define DEFAULT_HENON_Y 0.1


struct ArnoldCatMap {
  double x, y;
};
#define DEFAULT_ARNOLD_X 0.123
#define DEFAULT_ARNOLD_Y 0.456

struct SineMap {
  double x;
  double mu;
};
#define DEFAULT_SINE_X 0.123
#define DEFAULT_SINE_MU 0.99

struct ChebyshevMap {
  double x;
  int mu;
};
#define DEFAULT_CHEBYSHEV_X 0.7654
#define DEFAULT_CHEBYSHEV_MU 4

struct LorenzMap {
  double x, y, z;
  double sigma, rho, beta;
  double dt;
};
#define DEFAULT_LORENZ_X 0.1
#define DEFAULT_LORENZ_Y 0.1
#define DEFAULT_LORENZ_Z 0.1
#define DEFAULT_LORENZ_SIGMA 10.0
#define DEFAULT_LORENZ_RHO 28.0
#define DEFAULT_LORENZ_BETA (8.0 / 3.0)

struct ChenMap {
  double x, y, z;
  double a, b, c;
  double dt;
};
#define DEFAULT_CHEN_X 0.1
#define DEFAULT_CHEN_Y 0.1
#define DEFAULT_CHEN_Z 0.1
#define DEFAULT_CHEN_A 35.0
#define DEFAULT_CHEN_B 3.0
#define DEFAULT_CHEN_C 28.0

struct RosslerMap {
  double x, y, z;
  double a, b, c;
  double dt;
};
#define DEFAULT_ROSSLER_X 0.1
#define DEFAULT_ROSSLER_Y 0.1
#define DEFAULT_ROSSLER_Z 0.1
#define DEFAULT_ROSSLER_A 0.2
#define DEFAULT_ROSSLER_B 0.2
#define DEFAULT_ROSSLER_C 5.7

#define DEFAULT_DT 0.01


struct AES_CHAOS_ctx
{
  uint8_t OriginalKey[AES_CHAOS_KEYLEN];
  uint8_t RoundKey[AES_CHAOS_keyExpSize];
  uint8_t Iv[AES_CHAOS_BLOCKLEN];

  ChaosMap map;
  void* map_state;

  double W_t;
  double alpha;
  double beta;
  double gamma;
  double delta;
};

struct AES_CHAOS_GCM_result {
  uint8_t* buf;
  uint8_t tag[AES_CHAOS_GCM_TAGLEN];
};

size_t AES_CHAOS_get_heap_size(ChaosMap map_type);

void AES_CHAOS_init_ctx(struct AES_CHAOS_ctx* ctx, const uint8_t* key, ChaosMap map_type);
void AES_CHAOS_init_ctx_iv(struct AES_CHAOS_ctx* ctx, const uint8_t* key, const uint8_t* iv, ChaosMap map_type);
void AES_CHAOS_ctx_set_iv(struct AES_CHAOS_ctx* ctx, const uint8_t* iv);

void AES_CHAOS_ECB_encrypt(struct AES_CHAOS_ctx* ctx, uint8_t* buf);

void AES_CHAOS_GCM_authenticated_encrypt_buffer(struct AES_CHAOS_ctx* ctx, struct AES_CHAOS_GCM_result* res, size_t length, size_t iv_len, uint8_t* aad, size_t aad_length);

int AES_CHAOS_GCM_authenticated_decrypt_buffer(struct AES_CHAOS_ctx* ctx, struct AES_CHAOS_GCM_result* res, const uint8_t* tag, size_t length, size_t iv_len, uint8_t* aad, size_t aad_length);

#endif // _AES_CHAOS_H_