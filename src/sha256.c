#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const uint32_t SHA256_K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static const uint32_t SHA256_H0[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

uint32_t rotr(uint32_t x, uint32_t n)
{
    n &= 31U;
    return (n == 0) ? x : ((x >> n) | (x << (32U - n)));
}

uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t big_sigma0(uint32_t x)
{
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint32_t big_sigma1(uint32_t x)
{
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint32_t small_sigma0(uint32_t x)
{
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint32_t small_sigma1(uint32_t x)
{
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

uint8_t *sha256_pad(const uint8_t *message, size_t length, size_t *new_length)
{
    size_t padded_len = ((length + 8) / SHA256_BLOCK_SIZE + 1) * SHA256_BLOCK_SIZE;
    uint8_t *buffer = (uint8_t *)calloc(1, padded_len);
    if (!buffer) {
        if (new_length) *new_length = 0;
        return NULL;
    }

    if (message && length > 0) {
        memcpy(buffer, message, length);
    }
    buffer[length] = 0x80;

    uint64_t total_bits = (uint64_t)length * 8ULL;
    for (int i = 0; i < 8; i++) {
        buffer[padded_len - 1 - i] = (uint8_t)(total_bits >> (i * 8));
    }

    if (new_length) {
        *new_length = padded_len;
    }
    return buffer;
}

void sha256_transform(uint32_t state[8], const uint8_t block[SHA256_BLOCK_SIZE])
{
    uint32_t w[64];

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + SHA256_K[i] + w[i];
        uint32_t t2 = big_sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    memcpy(ctx->state, SHA256_H0, sizeof(SHA256_H0));
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx->state, ctx->data);
            ctx->bitlen += 512ULL;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t hash[SHA256_DIGEST_SIZE])
{
    uint64_t total_bits = ctx->bitlen + ((uint64_t)ctx->datalen * 8ULL);
    size_t pos = ctx->datalen;

    ctx->data[pos++] = 0x80;
    if (pos > 56) {
        while (pos < SHA256_BLOCK_SIZE) {
            ctx->data[pos++] = 0x00;
        }
        sha256_transform(ctx->state, ctx->data);
        memset(ctx->data, 0, 56);
    } else {
        while (pos < 56) {
            ctx->data[pos++] = 0x00;
        }
    }

    for (int i = 0; i < 8; i++) {
        ctx->data[56 + i] = (uint8_t)(total_bits >> ((7 - i) * 8));
    }
    sha256_transform(ctx->state, ctx->data);

    for (int j = 0; j < 8; j++) {
        hash[j * 4 + 0] = (uint8_t)((ctx->state[j] >> 24) & 0xff);
        hash[j * 4 + 1] = (uint8_t)((ctx->state[j] >> 16) & 0xff);
        hash[j * 4 + 2] = (uint8_t)((ctx->state[j] >> 8) & 0xff);
        hash[j * 4 + 3] = (uint8_t)(ctx->state[j] & 0xff);
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

void sha256d(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE])
{
    uint8_t first[SHA256_DIGEST_SIZE];
    sha256(data, len, first);
    sha256(first, SHA256_DIGEST_SIZE, hash);
}

void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i * 2]     = digits[(bytes[i] >> 4) & 0x0f];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    hex[len * 2] = '\0';
}

int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) {
        return -1;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int val = 0;
        if (sscanf(&hex[i * 2], "%2x", &val) != 1) {
            return -1;
        }
        bytes[i] = (uint8_t)val;
    }
    return (int)(hex_len / 2);
}

void bytes_reverse(uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t tmp = bytes[i];
        bytes[i] = bytes[len - 1 - i];
        bytes[len - 1 - i] = tmp;
    }
}
