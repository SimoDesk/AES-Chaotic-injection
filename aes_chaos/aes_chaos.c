/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <math.h>
#include <stdlib.h>
#include <string.h>
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

// iterate the logistic map following the equation x_{n+1} = p * x_n * (1 - x_n) and return the difference between the new and old value of x
static double iterateLogisticMap(void* state) {
  struct LogisticMap* map = (struct LogisticMap*) state;

  double x_old = map->x;

  map->x = map->p * map->x * (1 - map->x);

  // Return the difference between the new and old value of x, aka DELTA_W
  return map->x - x_old;
}

// Update the chaotic state and compute the new value of W_t based on the chaotic map and the parameters alpha, beta, gamma, and delta
static void updateChaos(struct AES_CHAOS_ctx* ctx) {
  double delta_w = 0.0;

  // Update the chaotic state based on the selected chaos map
  switch (ctx->map) {
    case LOGISTIC_MAP:
      delta_w = iterateLogisticMap(ctx->map_state);
      break;
    default:
      // Handle error: unknown chaos map
      return;
  }

  // Update W_t based on the chaotic map and the parameters alpha, beta, gamma, and delta
  ctx->W_t = ctx->W_t + (ctx->alpha * delta_w) - (ctx->beta * fabs(ctx->W_t));
}

// Reset the chaotic state and W_t to their initial values
static void resetChaos(struct AES_CHAOS_ctx* ctx) {
    ctx->W_t = 0.0;

    switch (ctx->map) {
        case LOGISTIC_MAP:
            if (ctx->map_state != NULL) {
                struct LogisticMap* map = (struct LogisticMap*)ctx->map_state;
                map->x = DEFAULT_LOGISTIC_X; // Reset to the default initial value
                map->p = DEFAULT_LOGISTIC_P; // Reset to the default parameter value
            }
            break;
        default:
            // Handle error: unknown chaos map
            break;
    }
}

// Compute the chaotic S-box value based on the current chaotic state and the input byte x
static uint8_t getChaoticSBoxValue_update(struct AES_CHAOS_ctx* ctx, uint8_t x) {
  // First, move forward the chaotic state and compute the new value of W_t
  updateChaos(ctx);

  // By using the standard construction of the S-Box, which is based on the multiplicative inverse in GF(2^8) followed by an affine transformation,
  // I can use it to calculate A * x^-1 (XOR) C without the need to compute the multiplicative inverse, which is a costly operation.
  uint8_t base_value = sbox[x];

  // Calculate the chaotic perturbation: gamma * tanh(delta * W(t))
  double chaos_modifier = ctx->gamma * tanh(ctx->delta * ctx->W_t);

  // Return the S-box value perturbed by the chaotic modifier, ensuring it is cast to uint8_t
  return (uint8_t) (base_value + (int)chaos_modifier);
}

// Compute the chaotic S-box value based on the current chaotic state and the input byte x without updating the chaotic state
static uint8_t getChaoticSBoxValue_static(struct AES_CHAOS_ctx* ctx, uint8_t x) {
  // By using the standard construction of the S-Box, which is based on the multiplicative inverse in GF(2^8) followed by an affine transformation,
  // I can use it to calculate A * x^-1 (XOR) C without the need to compute the multiplicative inverse, which is a costly operation.
  uint8_t base_value = sbox[x];

  // Calculate the chaotic perturbation: gamma * tanh(delta * W(t))
  double chaos_modifier = ctx->gamma * tanh(ctx->delta * ctx->W_t);

  // Return the S-box value perturbed by the chaotic modifier, ensuring it is cast to uint8_t
  return (uint8_t) (base_value + (int)chaos_modifier);
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
  ctx->W_t = 0.0;
  ctx->alpha = DEFAULT_APLHA;
  ctx->beta = DEFAULT_BETA;
  ctx->gamma = DEFAULT_GAMMA;
  ctx->delta = DEFAULT_DELTA;

  if (map_type == LOGISTIC_MAP) {
    // Nota: in un'applicazione reale, gestire il fallimento di malloc
    ctx->map_state = malloc(sizeof(struct LogisticMap)); 
    if (ctx->map_state == NULL) // Handle memory allocation failure
      return;

    struct LogisticMap* log_map = (struct LogisticMap*)ctx->map_state;
    log_map->p = DEFAULT_LOGISTIC_P;
    log_map->x = DEFAULT_LOGISTIC_X;
  }

  KeyExpansion(ctx, key);
}

void AES_CHAOS_init_ctx_iv(struct AES_CHAOS_ctx* ctx, const uint8_t* key, const uint8_t* iv, ChaosMap map_type)
{
  AES_CHAOS_init_ctx(ctx, key, map_type);
  memcpy(ctx->Iv, iv, AES_CHAOS_BLOCKLEN);
}

void AES_CHAOS_ctx_set_iv(struct AES_CHAOS_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_CHAOS_BLOCKLEN);
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

  // Reset the chaotic state and W_t before starting the encryption process
  resetChaos(ctx); 

  AddRoundKey(0, state, RoundKey);

  for (round = 1; ; ++round)
  {
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

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

static void AES_CHAOS_ECB_encrypt(struct AES_CHAOS_ctx* ctx, uint8_t* buf)
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

void AES_CHAOS_GCM_xcrypt_buffer(struct AES_CHAOS_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t buffer[AES_CHAOS_BLOCKLEN];
  
  size_t i;
  int bi;
  for (i = 0, bi = AES_CHAOS_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_CHAOS_BLOCKLEN)
    {
      memcpy(buffer, ctx->Iv, AES_CHAOS_BLOCKLEN);
      Cipher(ctx, (state_t*)buffer, ctx->RoundKey);

      for (bi = (AES_CHAOS_BLOCKLEN - 1); bi >= (AES_CHAOS_BLOCKLEN - 4); --bi)
      {
        if (ctx->Iv[bi] == 255)
	      {
          ctx->Iv[bi] = 0;
          continue;
        } 
        ctx->Iv[bi] += 1;
        break;   
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

void AES_CHAOS_GCM_authenticated_encrypt_buffer(struct AES_CHAOS_ctx* ctx, struct AES_CHAOS_GCM_result* res, size_t length, size_t iv_len, uint8_t* aad, size_t aad_length) {

  uint8_t H[AES_CHAOS_BLOCKLEN] = {0};
  AES_CHAOS_ECB_encrypt(ctx, H);
  
  uint8_t J[AES_CHAOS_BLOCKLEN] = {0};
  if(iv_len == 12) {
    memcpy(J, ctx->Iv, 12);
    J[12] = 0x00;
    J[13] = 0x00;
    J[14] = 0x00;
    J[15] = 0x01;
  } else {
    for (size_t i = 0; i < iv_len; i += AES_CHAOS_BLOCKLEN) {
      for (size_t j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
        if (i + j < iv_len)
          J[j] ^= ctx->Iv[i + j];
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

  uint8_t saved_iv_payload[AES_CHAOS_BLOCKLEN];
  memcpy(saved_iv_payload, ctx->Iv, AES_CHAOS_BLOCKLEN);

  memcpy(ctx->Iv, Jinc, AES_CHAOS_BLOCKLEN);
  AES_CHAOS_GCM_xcrypt_buffer(ctx, res->buf, length);

  memcpy(ctx->Iv, saved_iv_payload, AES_CHAOS_BLOCKLEN);

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

  uint8_t saved_iv_tag[AES_CHAOS_BLOCKLEN];
  memcpy(saved_iv_tag, ctx->Iv, AES_CHAOS_BLOCKLEN);

  memcpy(ctx->Iv, J, AES_CHAOS_BLOCKLEN);
  AES_CHAOS_GCM_xcrypt_buffer(ctx, S, AES_CHAOS_BLOCKLEN);

  memcpy(ctx->Iv, saved_iv_tag, AES_CHAOS_BLOCKLEN);

  memcpy(res->tag, S, AES_CHAOS_GCM_TAGLEN);
}

int AES_CHAOS_GCM_authenticated_decrypt_buffer(struct AES_CHAOS_ctx* ctx, struct AES_CHAOS_GCM_result* res, const uint8_t* tag, size_t length, size_t iv_len, uint8_t* aad, size_t aad_length) {
  
  uint8_t H[AES_CHAOS_BLOCKLEN] = {0};
  AES_CHAOS_ECB_encrypt(ctx, H);

  uint8_t J[AES_CHAOS_BLOCKLEN] = {0};
  if(iv_len == 12) {
    memcpy(J, ctx->Iv, 12);
    J[12] = 0x00; J[13] = 0x00; J[14] = 0x00; J[15] = 0x01;
  } else {
    for (size_t i = 0; i < iv_len; i += AES_CHAOS_BLOCKLEN) {
      for (size_t j = 0; j < AES_CHAOS_BLOCKLEN; j++) {
        if (i + j < iv_len)
          J[j] ^= ctx->Iv[i + j];
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

  uint8_t saved_iv_tag[AES_CHAOS_BLOCKLEN];
  memcpy(saved_iv_tag, ctx->Iv, AES_CHAOS_BLOCKLEN);

  memcpy(ctx->Iv, J, AES_CHAOS_BLOCKLEN);
  AES_CHAOS_GCM_xcrypt_buffer(ctx, S, AES_CHAOS_BLOCKLEN);

  memcpy(ctx->Iv, saved_iv_tag, AES_CHAOS_BLOCKLEN);

  uint8_t diff = 0;
  for (int i = 0; i < AES_CHAOS_GCM_TAGLEN; i++) {
    diff |= (S[i] ^ tag[i]);
  }
  
  if (diff != 0) {
    return 0;
  }

  uint8_t Jinc[AES_CHAOS_BLOCKLEN];
  memcpy(Jinc, J, AES_CHAOS_BLOCKLEN);
  counterInc32(Jinc); 

  uint8_t saved_iv_payload[AES_CHAOS_BLOCKLEN];
  memcpy(saved_iv_payload, ctx->Iv, AES_CHAOS_BLOCKLEN);

  memcpy(ctx->Iv, Jinc, AES_CHAOS_BLOCKLEN);
  AES_CHAOS_GCM_xcrypt_buffer(ctx, res->buf, length);

  memcpy(ctx->Iv, saved_iv_payload, AES_CHAOS_BLOCKLEN);

  return 1;
}