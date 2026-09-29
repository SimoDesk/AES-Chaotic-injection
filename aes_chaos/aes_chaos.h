#ifndef _AES_CHAOS_H_
#define _AES_CHAOS_H_

#include <stdint.h>
#include <stddef.h>

#define AES256 1

#define AES_CHAOS_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define AES_CHAOS_IVLEN 12 // IV length in bytes 
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

#define DEFAULT_APLHA 0.050
#define DEFAULT_BETA 0.001
#define DEFAULT_GAMMA 255
#define DEFAULT_DELTA 1

typedef enum {
  LOGISTIC_MAP
} ChaosMap;

#define DEFAULT_LOGISTIC_P 3.75
#define DEFAULT_LOGISTIC_X 0.5

struct LogisticMap {
  double x;
  double p;
};

struct AES_CHAOS_ctx
{
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

void AES_CHAOS_init_ctx(struct AES_CHAOS_ctx* ctx, const uint8_t* key, ChaosMap map_type);
void AES_CHAOS_init_ctx_iv(struct AES_CHAOS_ctx* ctx, const uint8_t* key, const uint8_t* iv, ChaosMap map_type);
void AES_CHAOS_ctx_set_iv(struct AES_CHAOS_ctx* ctx, const uint8_t* iv);

void AES_CHAOS_GCM_authenticated_encrypt_buffer(struct AES_CHAOS_ctx* ctx, struct AES_CHAOS_GCM_result* res, size_t length, size_t iv_len, uint8_t* aad, size_t aad_length);

int AES_CHAOS_GCM_authenticated_decrypt_buffer(struct AES_CHAOS_ctx* ctx, struct AES_CHAOS_GCM_result* res, const uint8_t* tag, size_t length, size_t iv_len, uint8_t* aad, size_t aad_length);

#endif // _AES_CHAOS_H_