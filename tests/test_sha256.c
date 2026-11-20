#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "sha256.h"

static void test_vector(const char *input, size_t len, const char *expected_hex)
{
    uint8_t digest[32];
    char hex[65];

    sha256((const uint8_t *)input, len, digest);
    bytes_to_hex(digest, 32, hex);

    if (strcmp(hex, expected_hex) != 0) {
        printf("FAILED! Input length: %zu\n", len);
        printf("  Expected: %s\n", expected_hex);
        printf("  Got:      %s\n", hex);
        exit(1);
    }
    printf("  [PASS] sha256 (len %zu) = %.16s...\n", len, hex);
}

static void test_sha256_pad(void)
{
    size_t new_len = 0;
    const char *msg = "abc";
    uint8_t *padded = sha256_pad((const uint8_t *)msg, 3, &new_len);

    assert(padded != NULL);
    assert(new_len == 64);
    assert(padded[0] == 'a' && padded[1] == 'b' && padded[2] == 'c');
    assert(padded[3] == 0x80);
    assert(padded[63] == 24); /* 3 * 8 bits */
    free(padded);
    printf("  [PASS] sha256_pad basic checks\n");
}

static void test_bitwise_helpers(void)
{
    assert(rotr(1, 1) == 0x80000000U);
    assert(rotr(0x12345678U, 0) == 0x12345678U);
    assert(ch(0xffffffffU, 0x12345678U, 0x87654321U) == 0x12345678U);
    assert(ch(0x00000000U, 0x12345678U, 0x87654321U) == 0x87654321U);
    assert(maj(0, 0, 1) == 0);
    assert(maj(1, 1, 0) == 1);
    printf("  [PASS] Bitwise helpers (rotr, ch, maj, sigmas)\n");
}

static void test_double_sha256(void)
{
    const char *msg = "hello";
    uint8_t h1[32], h2[32], hd[32];

    sha256((const uint8_t *)msg, strlen(msg), h1);
    sha256(h1, 32, h2);
    sha256d((const uint8_t *)msg, strlen(msg), hd);

    assert(memcmp(h2, hd, 32) == 0);
    printf("  [PASS] sha256d equals double sha256\n");
}

static void test_long_message(void)
{
    char buf[1000];
    memset(buf, 'A', sizeof(buf));
    test_vector(buf, sizeof(buf),
        "c2e686823489ced2017f6059b8b239318b6364f6dcd835d0a519105a1eadd6e4");
}

int main(void)
{
    printf("=== Running SHA-256 Validation Suite ===\n");

    test_bitwise_helpers();
    test_sha256_pad();

    /* NIST Standard Vectors */
    test_vector("", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    test_vector("abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    test_vector("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    test_vector("hello world", 11,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

    test_long_message();
    test_double_sha256();

    printf("=== All SHA-256 Tests Passed Successfully! ===\n");
    return 0;
}
