#define _POSIX_C_SOURCE 200809L
#include "tminer.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_BOLD    "\x1b[1m"
#define ANSI_COLOR_RESET   "\x1b[0m"

static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

int get_cpu_cores(void)
{
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    return (cores > 0) ? (int)cores : 4;
}

void tminer_init(void)
{
    /* Nothing to allocate globally yet */
}

void tminer_print_banner(void)
{
    printf(ANSI_COLOR_CYAN ANSI_COLOR_BOLD);
    printf("====================================================================\n");
    printf("  ████████╗███╗   ███╗██╗███╗   ██╗███████╗██████╗ \n");
    printf("  ╚══██╔══╝████╗ ████║██║████╗  ██║██╔════╝██╔══██╗\n");
    printf("     ██║   ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝\n");
    printf("     ██║   ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗\n");
    printf("     ██║   ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║\n");
    printf("     ╚═╝   ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\n");
    printf("          High-Performance C17 Proof-of-Work Miner\n");
    printf("====================================================================\n");
    printf(ANSI_COLOR_RESET "\n");
}

void bits_to_target(uint32_t bits, uint8_t target[32])
{
    memset(target, 0, 32);
    uint32_t exponent = (bits >> 24) & 0xff;
    uint32_t mantissa = bits & 0x007fffff;

    if (exponent <= 3) {
        mantissa >>= (8 * (3 - exponent));
        target[31] = (uint8_t)(mantissa & 0xff);
        target[30] = (uint8_t)((mantissa >> 8) & 0xff);
        target[29] = (uint8_t)((mantissa >> 16) & 0xff);
    } else {
        size_t offset = 32 - exponent;
        if (offset < 32) {
            target[offset] = (uint8_t)((mantissa >> 16) & 0xff);
        }
        if (offset + 1 < 32) {
            target[offset + 1] = (uint8_t)((mantissa >> 8) & 0xff);
        }
        if (offset + 2 < 32) {
            target[offset + 2] = (uint8_t)(mantissa & 0xff);
        }
    }
}

bool check_pow(const uint8_t hash_be[32], const uint8_t target[32])
{
    for (int i = 0; i < 32; i++) {
        if (hash_be[i] < target[i]) return true;
        if (hash_be[i] > target[i]) return false;
    }
    return true;
}

bool check_difficulty_zeros(const uint8_t hash_be[32], int hex_zeros)
{
    int full_bytes = hex_zeros / 2;
    int half_byte = hex_zeros % 2;

    for (int i = 0; i < full_bytes; i++) {
        if (hash_be[i] != 0) return false;
    }
    if (half_byte) {
        if ((hash_be[full_bytes] & 0xf0) != 0) return false;
    }
    return true;
}

void get_genesis_block(bitcoin_block_header_t *header)
{
    memset(header, 0, sizeof(*header));
    header->version = 1;
    memset(header->prev_block, 0, 32);
    /* Genesis Merkle root in internal little-endian byte order */
    hex_to_bytes("3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
                 header->merkle_root, 32);
    header->timestamp = 1231006505; /* Jan 03, 2009 */
    header->bits      = 0x1d00ffff;
    header->nonce     = 2083236893U;
}

void get_sample_block(bitcoin_block_header_t *header)
{
    memset(header, 0, sizeof(*header));
    header->version = 1;
    /* Block 125552 previous block in internal byte order */
    hex_to_bytes("1b099acc63b7443724e6d76c83c4806138f6819731b41c22881cd30000000000",
                 header->prev_block, 32);
    /* Block 125552 merkle root in internal byte order */
    hex_to_bytes("72a6eff894ed32b6710de61d7209f53e1221b673dcd4d6195f49e523e63b81da",
                 header->merkle_root, 32);
    header->timestamp = 1305998791;
    header->bits      = 0x1a44b9f2;
    header->nonce     = 2504433986U;
}

/* Worker thread argument for block header mining */
typedef struct {
    int thread_id;
    int num_threads;
    uint32_t start_nonce;
    uint32_t max_nonce;
    bitcoin_block_header_t header;
    uint8_t target[32];
    atomic_bool *stop_flag;
    atomic_uint_fast64_t *total_hash_counter;
    bool found;
    uint32_t found_nonce;
    uint8_t found_hash[32];
} block_miner_worker_t;

static void *block_miner_thread(void *arg)
{
    block_miner_worker_t *w = (block_miner_worker_t *)arg;
    bitcoin_block_header_t local_hdr = w->header;
    uint8_t digest[32];
    uint8_t hash_be[32];
    uint64_t local_hashes = 0;

    uint32_t stride = (uint32_t)w->num_threads;
    uint32_t nonce = w->start_nonce + (uint32_t)w->thread_id;

    while (nonce <= w->max_nonce) {
        if ((local_hashes & 0x3ffff) == 0) {
            atomic_fetch_add(w->total_hash_counter, local_hashes);
            local_hashes = 0;
            if (atomic_load(w->stop_flag)) {
                break;
            }
        }
        local_hashes++;

        local_hdr.nonce = nonce;
        sha256d((const uint8_t *)&local_hdr, sizeof(local_hdr), digest);

        for (int k = 0; k < 32; k++) {
            hash_be[k] = digest[31 - k];
        }

        if (check_pow(hash_be, w->target)) {
            w->found = true;
            w->found_nonce = nonce;
            memcpy(w->found_hash, hash_be, 32);
            atomic_store(w->stop_flag, true);
            break;
        }

        if (__builtin_add_overflow(nonce, stride, &nonce)) {
            break;
        }
    }

    atomic_fetch_add(w->total_hash_counter, local_hashes);
    return NULL;
}

int tminer_mine_block(const bitcoin_block_header_t *template_header,
                      uint32_t start_nonce,
                      uint32_t max_nonce,
                      int num_threads,
                      tminer_result_t *result)
{
    if (num_threads <= 0) {
        num_threads = get_cpu_cores();
    }

    uint8_t target[32];
    bits_to_target(template_header->bits, target);

    char target_hex[65];
    bytes_to_hex(target, 32, target_hex);

    printf(ANSI_COLOR_CYAN "[*] Starting Block Mining...\n" ANSI_COLOR_RESET);
    printf("    Target:  %s\n", target_hex);
    printf("    Bits:    0x%08X\n", template_header->bits);
    printf("    Threads: %d\n", num_threads);
    printf("    Range:   [%u, %u]\n\n", start_nonce, max_nonce);

    atomic_bool stop_flag = false;
    atomic_uint_fast64_t total_hashes = 0;

    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
    block_miner_worker_t *workers = malloc(sizeof(block_miner_worker_t) * num_threads);

    double t0 = get_time_sec();

    for (int i = 0; i < num_threads; i++) {
        workers[i].thread_id = i;
        workers[i].num_threads = num_threads;
        workers[i].start_nonce = start_nonce;
        workers[i].max_nonce = max_nonce;
        workers[i].header = *template_header;
        memcpy(workers[i].target, target, 32);
        workers[i].stop_flag = &stop_flag;
        workers[i].total_hash_counter = &total_hashes;
        workers[i].found = false;
        pthread_create(&threads[i], NULL, block_miner_thread, &workers[i]);
    }

    /* Live monitor */
    while (!atomic_load(&stop_flag)) {
        struct timespec sleep_ts = {0, 250000000L}; /* 250 ms */
        nanosleep(&sleep_ts, NULL);
        double now = get_time_sec();
        double elapsed = now - t0;
        uint64_t hashes = atomic_load(&total_hashes);
        double rate = (elapsed > 0) ? ((double)hashes / elapsed) : 0;
        printf("\r" ANSI_COLOR_YELLOW "[Mining] Hashes: %lu | Elapsed: %.2fs | Hashrate: %.2f MH/s" ANSI_COLOR_RESET " ",
               (unsigned long)hashes, elapsed, rate / 1e6);
        fflush(stdout);

        /* Check if all finished */
        bool any_alive = false;
        for (int i = 0; i < num_threads; i++) {
            if (!workers[i].found) {
                any_alive = true;
            }
        }
        if (!any_alive) break;
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    double t1 = get_time_sec();
    double total_elapsed = t1 - t0;
    uint64_t final_hashes = atomic_load(&total_hashes);
    double avg_rate = (total_elapsed > 0) ? ((double)final_hashes / total_elapsed) : 0;

    memset(result, 0, sizeof(*result));
    result->total_hashes = final_hashes;
    result->elapsed_seconds = total_elapsed;
    result->hashrate = avg_rate;

    for (int i = 0; i < num_threads; i++) {
        if (workers[i].found) {
            result->found = true;
            result->nonce = workers[i].found_nonce;
            memcpy(result->hash, workers[i].found_hash, 32);
            break;
        }
    }

    free(threads);
    free(workers);

    printf("\n\n");
    if (result->found) {
        char hash_hex[65];
        bytes_to_hex(result->hash, 32, hash_hex);
        printf(ANSI_COLOR_GREEN ANSI_COLOR_BOLD "[+] Valid Block Found!" ANSI_COLOR_RESET "\n");
        printf("    Nonce:    %u (0x%08X)\n", result->nonce, result->nonce);
        printf("    Hash:     %s\n", hash_hex);
        printf("    Target:   %s\n", target_hex);
        printf("    Hashes:   %lu in %.2f seconds\n", (unsigned long)result->total_hashes, result->elapsed_seconds);
        printf("    Hashrate: %.2f MH/s\n", result->hashrate / 1e6);
        return 0;
    } else {
        printf(ANSI_COLOR_RED "[-] No matching block found in given nonce range.\n" ANSI_COLOR_RESET);
        printf("    Tested: %lu hashes in %.2f seconds\n", (unsigned long)result->total_hashes, result->elapsed_seconds);
        return 1;
    }
}

/* Worker thread argument for string mining */
typedef struct {
    int thread_id;
    int num_threads;
    uint32_t start_nonce;
    uint32_t max_nonce;
    const char *prefix;
    size_t prefix_len;
    int hex_zeros;
    atomic_bool *stop_flag;
    atomic_uint_fast64_t *total_hash_counter;
    bool found;
    uint32_t found_nonce;
    uint8_t found_hash[32];
} string_miner_worker_t;

static void *string_miner_thread(void *arg)
{
    string_miner_worker_t *w = (string_miner_worker_t *)arg;
    char buffer[256];
    uint8_t digest[32];
    uint8_t hash_be[32];
    uint64_t local_hashes = 0;

    uint32_t stride = (uint32_t)w->num_threads;
    uint32_t nonce = w->start_nonce + (uint32_t)w->thread_id;

    while (nonce <= w->max_nonce) {
        if ((local_hashes & 0x3ffff) == 0) {
            atomic_fetch_add(w->total_hash_counter, local_hashes);
            local_hashes = 0;
            if (atomic_load(w->stop_flag)) {
                break;
            }
        }
        local_hashes++;

        int len = snprintf(buffer, sizeof(buffer), "%s%u", w->prefix, nonce);
        sha256d((const uint8_t *)buffer, (size_t)len, digest);

        for (int k = 0; k < 32; k++) {
            hash_be[k] = digest[31 - k];
        }

        if (check_difficulty_zeros(hash_be, w->hex_zeros)) {
            w->found = true;
            w->found_nonce = nonce;
            memcpy(w->found_hash, hash_be, 32);
            atomic_store(w->stop_flag, true);
            break;
        }

        if (__builtin_add_overflow(nonce, stride, &nonce)) {
            break;
        }
    }

    atomic_fetch_add(w->total_hash_counter, local_hashes);
    return NULL;
}

int tminer_mine_string(const char *prefix,
                       int hex_zeros,
                       uint32_t start_nonce,
                       uint32_t max_nonce,
                       int num_threads,
                       tminer_result_t *result)
{
    if (num_threads <= 0) {
        num_threads = get_cpu_cores();
    }
    if (hex_zeros <= 0) {
        hex_zeros = 4;
    }

    printf(ANSI_COLOR_CYAN "[*] Starting Custom String Mining...\n" ANSI_COLOR_RESET);
    printf("    Prefix:     \"%s\"\n", prefix ? prefix : "");
    printf("    Difficulty: %d leading hex zeros\n", hex_zeros);
    printf("    Threads:    %d\n", num_threads);
    printf("    Range:      [%u, %u]\n\n", start_nonce, max_nonce);

    atomic_bool stop_flag = false;
    atomic_uint_fast64_t total_hashes = 0;

    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
    string_miner_worker_t *workers = malloc(sizeof(string_miner_worker_t) * num_threads);

    double t0 = get_time_sec();

    for (int i = 0; i < num_threads; i++) {
        workers[i].thread_id = i;
        workers[i].num_threads = num_threads;
        workers[i].start_nonce = start_nonce;
        workers[i].max_nonce = max_nonce;
        workers[i].prefix = prefix;
        workers[i].prefix_len = prefix ? strlen(prefix) : 0;
        workers[i].hex_zeros = hex_zeros;
        workers[i].stop_flag = &stop_flag;
        workers[i].total_hash_counter = &total_hashes;
        workers[i].found = false;
        pthread_create(&threads[i], NULL, string_miner_thread, &workers[i]);
    }

    while (!atomic_load(&stop_flag)) {
        struct timespec sleep_ts = {0, 200000000L}; /* 200 ms */
        nanosleep(&sleep_ts, NULL);
        double now = get_time_sec();
        double elapsed = now - t0;
        uint64_t hashes = atomic_load(&total_hashes);
        double rate = (elapsed > 0) ? ((double)hashes / elapsed) : 0;
        printf("\r" ANSI_COLOR_YELLOW "[Mining] Hashes: %lu | Elapsed: %.2fs | Hashrate: %.2f MH/s" ANSI_COLOR_RESET " ",
               (unsigned long)hashes, elapsed, rate / 1e6);
        fflush(stdout);

        bool any_running = false;
        for (int i = 0; i < num_threads; i++) {
            if (!workers[i].found) any_running = true;
        }
        if (!any_running) break;
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    double t1 = get_time_sec();
    double total_elapsed = t1 - t0;
    uint64_t final_hashes = atomic_load(&total_hashes);
    double avg_rate = (total_elapsed > 0) ? ((double)final_hashes / total_elapsed) : 0;

    memset(result, 0, sizeof(*result));
    result->total_hashes = final_hashes;
    result->elapsed_seconds = total_elapsed;
    result->hashrate = avg_rate;

    for (int i = 0; i < num_threads; i++) {
        if (workers[i].found) {
            result->found = true;
            result->nonce = workers[i].found_nonce;
            memcpy(result->hash, workers[i].found_hash, 32);
            break;
        }
    }

    free(threads);
    free(workers);

    printf("\n\n");
    if (result->found) {
        char hash_hex[65];
        bytes_to_hex(result->hash, 32, hash_hex);
        printf(ANSI_COLOR_GREEN ANSI_COLOR_BOLD "[+] Solution Found!" ANSI_COLOR_RESET "\n");
        printf("    Nonce:       %u\n", result->nonce);
        printf("    Payload:     \"%s%u\"\n", prefix, result->nonce);
        printf("    Hash (PoW):  %s\n", hash_hex);
        printf("    Hashes:      %lu in %.2f seconds\n", (unsigned long)result->total_hashes, result->elapsed_seconds);
        printf("    Hashrate:    %.2f MH/s\n", result->hashrate / 1e6);
        return 0;
    } else {
        printf(ANSI_COLOR_RED "[-] Solution not found in given range.\n" ANSI_COLOR_RESET);
        return 1;
    }
}

/* Benchmark worker thread */
typedef struct {
    atomic_bool *stop_flag;
    uint64_t count;
} bench_worker_t;

static void *benchmark_thread(void *arg)
{
    bench_worker_t *w = (bench_worker_t *)arg;
    uint8_t payload[80];
    memset(payload, 0x42, sizeof(payload));
    uint8_t digest[32];
    uint64_t c = 0;

    while (!atomic_load(w->stop_flag)) {
        payload[0] = (uint8_t)c;
        sha256d(payload, sizeof(payload), digest);
        c++;
    }
    w->count = c;
    return NULL;
}

void tminer_benchmark(int num_threads, double duration_seconds)
{
    if (num_threads <= 0) {
        num_threads = get_cpu_cores();
    }
    if (duration_seconds <= 0) {
        duration_seconds = 3.0;
    }

    printf(ANSI_COLOR_CYAN "[*] Running Benchmark (Double-SHA256, 80-byte Block Headers)...\n" ANSI_COLOR_RESET);
    printf("    Threads:  %d\n", num_threads);
    printf("    Duration: %.1f seconds\n\n", duration_seconds);

    atomic_bool stop_flag = false;
    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
    bench_worker_t *workers = malloc(sizeof(bench_worker_t) * num_threads);

    for (int i = 0; i < num_threads; i++) {
        workers[i].stop_flag = &stop_flag;
        workers[i].count = 0;
        pthread_create(&threads[i], NULL, benchmark_thread, &workers[i]);
    }

    double t0 = get_time_sec();
    struct timespec sleep_duration;
    sleep_duration.tv_sec = (time_t)duration_seconds;
    sleep_duration.tv_nsec = (long)((duration_seconds - (double)sleep_duration.tv_sec) * 1e9);
    nanosleep(&sleep_duration, NULL);

    atomic_store(&stop_flag, true);

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    double t1 = get_time_sec();
    double actual_time = t1 - t0;

    uint64_t total = 0;
    for (int i = 0; i < num_threads; i++) {
        total += workers[i].count;
    }

    double hashrate = (actual_time > 0) ? ((double)total / actual_time) : 0;

    printf(ANSI_COLOR_GREEN ANSI_COLOR_BOLD "[+] Benchmark Finished!" ANSI_COLOR_RESET "\n");
    printf("    Total Double-SHA256 Hashes: %lu\n", (unsigned long)total);
    printf("    Actual Time:                %.3f seconds\n", actual_time);
    printf("    Overall Hashrate:           " ANSI_COLOR_CYAN ANSI_COLOR_BOLD "%.2f MH/s (%.2f kH/s)" ANSI_COLOR_RESET "\n",
           hashrate / 1e6, hashrate / 1e3);
    printf("    Per-Thread Hashrate:        %.2f kH/s\n\n", (hashrate / num_threads) / 1e3);

    free(threads);
    free(workers);
}
