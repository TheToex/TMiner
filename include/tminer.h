#ifndef TMINER_H
#define TMINER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#pragma pack(push, 1)
typedef struct {
    uint32_t version;
    uint8_t  prev_block[32];
    uint8_t  merkle_root[32];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
} bitcoin_block_header_t;
#pragma pack(pop)

typedef struct {
    bool     found;
    uint32_t nonce;
    uint8_t  hash[32];         /* Standard reversed display format */
    uint64_t total_hashes;
    double   elapsed_seconds;
    double   hashrate;         /* Hashes per second */
} tminer_result_t;

/* Initialization and banner */
void tminer_init(void);
void tminer_print_banner(void);
int  get_cpu_cores(void);

/* Proof-of-Work target calculations */
void bits_to_target(uint32_t bits, uint8_t target[32]);
bool check_pow(const uint8_t hash_be[32], const uint8_t target[32]);
bool check_difficulty_zeros(const uint8_t hash_be[32], int hex_zeros);

/* Preset block headers */
void get_genesis_block(bitcoin_block_header_t *header);
void get_sample_block(bitcoin_block_header_t *header);

/* Multi-threaded Mining Engines */
int tminer_mine_block(const bitcoin_block_header_t *template_header,
                      uint32_t start_nonce,
                      uint32_t max_nonce,
                      int num_threads,
                      tminer_result_t *result);

int tminer_mine_string(const char *prefix,
                       int hex_zeros,
                       uint32_t start_nonce,
                       uint32_t max_nonce,
                       int num_threads,
                       tminer_result_t *result);

/* Benchmark */
void tminer_benchmark(int num_threads, double duration_seconds);

#endif
