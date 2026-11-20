#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

/* SHA-256 context for streaming hashing */
typedef struct {
    uint8_t  data[SHA256_BLOCK_SIZE];
    size_t   datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx_t;

/* Core bitwise helper functions */
uint32_t rotr(uint32_t x, uint32_t n);
uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
uint32_t big_sigma0(uint32_t x);
uint32_t big_sigma1(uint32_t x);
uint32_t small_sigma0(uint32_t x);
uint32_t small_sigma1(uint32_t x);

/* Message padding helper (caller must free returned buffer) */
uint8_t *sha256_pad(const uint8_t *message,
                    size_t length,
                    size_t *new_length);

/* Streaming SHA-256 API */
void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t hash[SHA256_DIGEST_SIZE]);
void sha256_transform(uint32_t state[8], const uint8_t block[SHA256_BLOCK_SIZE]);

/* One-shot SHA-256 */
void sha256(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE]);

/* Double SHA-256 (sha256d / hash256 used in Bitcoin) */
void sha256d(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE]);

/* Hex and byte utilities */
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex);
int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len);
void bytes_reverse(uint8_t *bytes, size_t len);

#endif
