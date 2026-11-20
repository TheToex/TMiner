#define _POSIX_C_SOURCE 200809L
#include "stratum.h"
#include "tminer.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_BOLD    "\x1b[1m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define MAX_MERKLE_BRANCHES 32
#define MAX_COINBASE_SIZE   2048

static volatile sig_atomic_t g_running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void diff_to_target(double diff, uint8_t target[32])
{
    memset(target, 0, 32);
    if (diff <= 0.0) {
        memset(target, 0xff, 32);
        return;
    }

    double val = 65535.0 / diff;
    int exp = 208;
    while (val >= 256.0) {
        val /= 256.0;
        exp += 8;
    }
    while (val < 1.0 && exp > 0) {
        val *= 256.0;
        exp -= 8;
    }

    int top_byte = 31 - (exp / 8);
    for (int i = 0; i < 8; i++) {
        int byte_val = (int)val;
        int idx = top_byte + i;
        if (idx >= 0 && idx < 32) {
            target[idx] = (uint8_t)(byte_val & 0xff);
        }
        val = (val - (double)byte_val) * 256.0;
    }
}

/* Thread-safe Stratum Job State */
typedef struct {
    char job_id[128];
    char prevhash_hex[65];
    char coinb1_hex[MAX_COINBASE_SIZE];
    char coinb2_hex[MAX_COINBASE_SIZE];
    char merkle_branches_hex[MAX_MERKLE_BRANCHES][65];
    int  merkle_branch_count;
    char version_hex[16];
    char nbits_hex[16];
    char ntime_hex[16];
    bool clean_jobs;

    /* Computed block header template */
    bitcoin_block_header_t header;
    uint8_t share_target[32];
    uint8_t network_target[32];
    char    extranonce2_hex[32];

    uint64_t job_generation;
} stratum_job_t;

/* Global miner context */
typedef struct {
    int sock;
    pthread_mutex_t sock_mutex;
    pthread_mutex_t job_mutex;

    char extranonce1_hex[64];
    int  extranonce2_size;
    double current_diff;

    stratum_job_t current_job;

    atomic_uint_fast64_t total_hashes;
    atomic_uint_fast32_t shares_accepted;
    atomic_uint_fast32_t shares_rejected;
    atomic_uint_fast32_t blocks_found;

    atomic_bool stop_workers;
    int num_threads;
    char user[256];
} stratum_ctx_t;

static int stratum_send(stratum_ctx_t *ctx, const char *msg)
{
    pthread_mutex_lock(&ctx->sock_mutex);
    size_t len = strlen(msg);
    ssize_t sent = send(ctx->sock, msg, len, 0);
    pthread_mutex_unlock(&ctx->sock_mutex);
    return (sent == (ssize_t)len) ? 0 : -1;
}

/* Build block header from active job */
static void build_block_header(stratum_ctx_t *ctx)
{
    stratum_job_t *job = &ctx->current_job;

    /* 1. Build Coinbase Transaction: coinb1 + extranonce1 + extranonce2 + coinb2 */
    char coinbase_hex[MAX_COINBASE_SIZE * 2 + 128];
    snprintf(coinbase_hex, sizeof(coinbase_hex), "%s%s%s%s",
             job->coinb1_hex, ctx->extranonce1_hex, job->extranonce2_hex, job->coinb2_hex);

    size_t cb_hex_len = strlen(coinbase_hex);
    uint8_t *coinbase_bin = malloc(cb_hex_len / 2 + 1);
    if (!coinbase_bin) return;
    int cb_len = hex_to_bytes(coinbase_hex, coinbase_bin, cb_hex_len / 2 + 1);
    if (cb_len <= 0) {
        free(coinbase_bin);
        return;
    }

    uint8_t coinbase_hash[32];
    sha256d(coinbase_bin, (size_t)cb_len, coinbase_hash);
    free(coinbase_bin);

    /* 2. Compute Merkle Root */
    uint8_t merkle_root[32];
    memcpy(merkle_root, coinbase_hash, 32);

    for (int i = 0; i < job->merkle_branch_count; i++) {
        uint8_t branch_bin[32];
        hex_to_bytes(job->merkle_branches_hex[i], branch_bin, 32);

        uint8_t combined[64];
        memcpy(combined, merkle_root, 32);
        memcpy(combined + 32, branch_bin, 32);
        sha256d(combined, 64, merkle_root);
    }

    /* 3. Assemble 80-byte Block Header */
    memset(&job->header, 0, sizeof(job->header));
    job->header.version = (uint32_t)strtoul(job->version_hex, NULL, 16);

    /* Stratum prevhash: 8 words of 4 bytes, byte-swap each word */
    for (int w = 0; w < 8; w++) {
        char word_hex[9];
        memcpy(word_hex, job->prevhash_hex + w * 8, 8);
        word_hex[8] = '\0';
        uint8_t wb[4];
        hex_to_bytes(word_hex, wb, 4);
        bytes_reverse(wb, 4);
        memcpy(job->header.prev_block + w * 4, wb, 4);
    }

    memcpy(job->header.merkle_root, merkle_root, 32);
    job->header.timestamp = (uint32_t)strtoul(job->ntime_hex, NULL, 16);
    job->header.bits      = (uint32_t)strtoul(job->nbits_hex, NULL, 16);
    job->header.nonce     = 0;

    /* Compute network target from bits */
    bits_to_target(job->header.bits, job->network_target);
    diff_to_target(ctx->current_diff, job->share_target);
}

/* Worker thread for Stratum mining */
typedef struct {
    int thread_id;
    stratum_ctx_t *ctx;
} stratum_worker_t;

static void *stratum_mining_worker(void *arg)
{
    stratum_worker_t *w = (stratum_worker_t *)arg;
    stratum_ctx_t *ctx = w->ctx;

    uint64_t last_gen = 0;
    bitcoin_block_header_t local_hdr;
    uint8_t share_target[32];
    uint8_t network_target[32];
    char job_id[128];
    char ntime_hex[16];
    char extranonce2_hex[32];

    uint32_t stride = (uint32_t)ctx->num_threads;
    uint32_t nonce = (uint32_t)w->thread_id * 10000000U;

    uint8_t digest[32];
    uint8_t hash_be[32];
    uint64_t local_hashes = 0;

    while (g_running && !atomic_load(&ctx->stop_workers)) {
        /* Check if a new job has arrived */
        pthread_mutex_lock(&ctx->job_mutex);
        if (ctx->current_job.job_generation != last_gen && ctx->current_job.job_id[0] != '\0') {
            last_gen = ctx->current_job.job_generation;
            local_hdr = ctx->current_job.header;
            memcpy(share_target, ctx->current_job.share_target, 32);
            memcpy(network_target, ctx->current_job.network_target, 32);
            snprintf(job_id, sizeof(job_id), "%s", ctx->current_job.job_id);
            snprintf(ntime_hex, sizeof(ntime_hex), "%s", ctx->current_job.ntime_hex);
            snprintf(extranonce2_hex, sizeof(extranonce2_hex), "%s", ctx->current_job.extranonce2_hex);
            nonce = (uint32_t)w->thread_id * 5000000U;
        }
        pthread_mutex_unlock(&ctx->job_mutex);

        if (last_gen == 0) {
            struct timespec ts = {0, 50000000L}; /* 50ms */
            nanosleep(&ts, NULL);
            continue;
        }

        /* Hash loop batch */
        for (int i = 0; i < 4096; i++) {
            local_hdr.nonce = nonce;
            sha256d((const uint8_t *)&local_hdr, sizeof(local_hdr), digest);

            for (int k = 0; k < 32; k++) {
                hash_be[k] = digest[31 - k];
            }

            /* Check if Share Target is met */
            if (check_pow(hash_be, share_target)) {
                char hash_hex[65];
                bytes_to_hex(hash_be, 32, hash_hex);

                bool is_block = check_pow(hash_be, network_target);

                if (is_block) {
                    atomic_fetch_add(&ctx->blocks_found, 1);
                    printf("\n\n" ANSI_COLOR_GREEN ANSI_COLOR_BOLD
                           "====================================================================\n"
                           " [🎉🎉🎉] VALID BITCOIN BLOCK FOUND ON NETWORK! [🎉🎉🎉]\n"
                           " Hash:   %s\n"
                           " Nonce:  0x%08x (%u)\n"
                           " Reward: 3.125 BTC + Fees!\n"
                           "====================================================================\n"
                           ANSI_COLOR_RESET "\n", hash_hex, nonce, nonce);
                } else {
                    printf("\n" ANSI_COLOR_CYAN "[+] Share Found (Thread %d)! Nonce: 0x%08x | Hash: %.16s..." ANSI_COLOR_RESET "\n",
                           w->thread_id, nonce, hash_hex);
                }

                /* Submit share to Stratum pool */
                char submit_msg[512];
                snprintf(submit_msg, sizeof(submit_msg),
                         "{\"id\": 4, \"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%08x\"]}\n",
                         ctx->user, job_id, extranonce2_hex, ntime_hex, nonce);
                stratum_send(ctx, submit_msg);
            }

            nonce += stride;
            local_hashes++;
        }

        atomic_fetch_add(&ctx->total_hashes, local_hashes);
        local_hashes = 0;
    }

    atomic_fetch_add(&ctx->total_hashes, local_hashes);
    return NULL;
}

/* Parse incoming Stratum JSON message */
static void handle_stratum_message(stratum_ctx_t *ctx, const char *line)
{
    if (strstr(line, "\"mining.set_difficulty\"")) {
        const char *p = strstr(line, "\"params\"");
        if (p) {
            const char *lb = strchr(p, '[');
            if (lb) {
                double diff = strtod(lb + 1, NULL);
                if (diff > 0.0) {
                    pthread_mutex_lock(&ctx->job_mutex);
                    ctx->current_diff = diff;
                    diff_to_target(diff, ctx->current_job.share_target);
                    pthread_mutex_unlock(&ctx->job_mutex);
                    printf(ANSI_COLOR_YELLOW "[*] Pool set difficulty: %.4f" ANSI_COLOR_RESET "\n", diff);
                }
            }
        }
        return;
    }

    if (strstr(line, "\"mining.notify\"")) {
        const char *p = strstr(line, "\"params\"");
        if (!p) return;
        const char *lb = strchr(p, '[');
        if (!lb) return;
        lb++;

        pthread_mutex_lock(&ctx->job_mutex);
        stratum_job_t *job = &ctx->current_job;

        /* Extract params: job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs */
        char *copy = strdup(lb);
        char *ptr = copy;

        /* Param 0: job_id */
        char *q1 = strchr(ptr, '\"');
        if (q1) {
            char *q2 = strchr(q1 + 1, '\"');
            if (q2) {
                *q2 = '\0';
                strncpy(job->job_id, q1 + 1, sizeof(job->job_id) - 1);
                ptr = q2 + 1;
            }
        }

        /* Param 1: prevhash */
        q1 = strchr(ptr, '\"');
        if (q1) {
            char *q2 = strchr(q1 + 1, '\"');
            if (q2) {
                *q2 = '\0';
                strncpy(job->prevhash_hex, q1 + 1, sizeof(job->prevhash_hex) - 1);
                ptr = q2 + 1;
            }
        }

        /* Param 2: coinb1 */
        q1 = strchr(ptr, '\"');
        if (q1) {
            char *q2 = strchr(q1 + 1, '\"');
            if (q2) {
                *q2 = '\0';
                strncpy(job->coinb1_hex, q1 + 1, sizeof(job->coinb1_hex) - 1);
                ptr = q2 + 1;
            }
        }

        /* Param 3: coinb2 */
        q1 = strchr(ptr, '\"');
        if (q1) {
            char *q2 = strchr(q1 + 1, '\"');
            if (q2) {
                *q2 = '\0';
                strncpy(job->coinb2_hex, q1 + 1, sizeof(job->coinb2_hex) - 1);
                ptr = q2 + 1;
            }
        }

        /* Param 4: merkle_branch array */
        job->merkle_branch_count = 0;
        char *mb_start = strchr(ptr, '[');
        if (mb_start) {
            char *mb_end = strchr(mb_start, ']');
            if (mb_end) {
                *mb_end = '\0';
                char *mptr = mb_start + 1;
                while ((q1 = strchr(mptr, '\"')) && job->merkle_branch_count < MAX_MERKLE_BRANCHES) {
                    char *q2 = strchr(q1 + 1, '\"');
                    if (!q2) break;
                    *q2 = '\0';
                    strncpy(job->merkle_branches_hex[job->merkle_branch_count++],
                            q1 + 1, 64);
                    mptr = q2 + 1;
                }
                ptr = mb_end + 1;
            }
        }

        /* Param 5: version */
        q1 = strchr(ptr, '\"');
        if (q1) {
            char *q2 = strchr(q1 + 1, '\"');
            if (q2) {
                *q2 = '\0';
                strncpy(job->version_hex, q1 + 1, sizeof(job->version_hex) - 1);
                ptr = q2 + 1;
            }
        }

        /* Param 6: nbits */
        q1 = strchr(ptr, '\"');
        if (q1) {
            char *q2 = strchr(q1 + 1, '\"');
            if (q2) {
                *q2 = '\0';
                strncpy(job->nbits_hex, q1 + 1, sizeof(job->nbits_hex) - 1);
                ptr = q2 + 1;
            }
        }

        /* Param 7: ntime */
        q1 = strchr(ptr, '\"');
        if (q1) {
            char *q2 = strchr(q1 + 1, '\"');
            if (q2) {
                *q2 = '\0';
                strncpy(job->ntime_hex, q1 + 1, sizeof(job->ntime_hex) - 1);
                ptr = q2 + 1;
            }
        }

        /* Param 8: clean_jobs */
        job->clean_jobs = (strstr(ptr, "true") != NULL);
        free(copy);

        /* Set extranonce2 (e.g. 8 bytes of zeroes) */
        memset(job->extranonce2_hex, '0', ctx->extranonce2_size * 2);
        job->extranonce2_hex[ctx->extranonce2_size * 2] = '\0';
        if (ctx->extranonce2_size >= 4) {
            job->extranonce2_hex[ctx->extranonce2_size * 2 - 1] = '1';
        }

        build_block_header(ctx);
        job->job_generation++;
        pthread_mutex_unlock(&ctx->job_mutex);

        printf(ANSI_COLOR_BLUE "[*] New Job: %s | Prev: %.16s... | Clean: %s" ANSI_COLOR_RESET "\n",
               job->job_id, job->prevhash_hex, job->clean_jobs ? "yes" : "no");
        return;
    }

    /* Response to mining.submit */
    if (strstr(line, "\"id\":4") || strstr(line, "\"id\": 4")) {
        if (strstr(line, "\"result\":true") || strstr(line, "\"result\": true")) {
            atomic_fetch_add(&ctx->shares_accepted, 1);
            printf(ANSI_COLOR_GREEN ANSI_COLOR_BOLD "[✓] Share Accepted by Pool!" ANSI_COLOR_RESET "\n");
        } else {
            atomic_fetch_add(&ctx->shares_rejected, 1);
            printf(ANSI_COLOR_RED "[-] Share Rejected by Pool: %s" ANSI_COLOR_RESET "\n", line);
        }
        return;
    }

    /* Response to mining.authorize */
    if (strstr(line, "\"id\":2") || strstr(line, "\"id\": 2")) {
        if (strstr(line, "\"result\":true") || strstr(line, "\"result\": true")) {
            printf(ANSI_COLOR_GREEN "[+] Worker Authorized successfully!" ANSI_COLOR_RESET "\n");
        } else {
            printf(ANSI_COLOR_YELLOW "[!] Authorize response: %s" ANSI_COLOR_RESET "\n", line);
        }
        return;
    }
}

int stratum_mine(const stratum_config_t *config)
{
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf(ANSI_COLOR_CYAN ANSI_COLOR_BOLD);
    printf("====================================================================\n");
    printf("              TMiner Stratum V1 Live Network Client                 \n");
    printf("====================================================================\n" ANSI_COLOR_RESET);
    int threads = (config->num_threads > 0) ? config->num_threads : get_cpu_cores();
    printf("  Pool:    %s:%d\n", config->host, config->port);
    printf("  User:    %s\n", config->user);
    printf("  Threads: %d\n\n", threads);

    /* 1. Connect to Pool via TCP */
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", config->port);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    printf("[*] Connecting to %s:%s...\n", config->host, port_str);
    if (getaddrinfo(config->host, port_str, &hints, &res) != 0) {
        fprintf(stderr, ANSI_COLOR_RED "[-] Failed to resolve hostname: %s\n" ANSI_COLOR_RESET, config->host);
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        fprintf(stderr, ANSI_COLOR_RED "[-] Could not connect to %s:%s\n" ANSI_COLOR_RESET, config->host, port_str);
        return -1;
    }
    printf(ANSI_COLOR_GREEN "[+] Connected successfully!" ANSI_COLOR_RESET "\n");

    /* Initialize context */
    stratum_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.sock = sock;
    pthread_mutex_init(&ctx.sock_mutex, NULL);
    pthread_mutex_init(&ctx.job_mutex, NULL);
    ctx.num_threads = threads;
    snprintf(ctx.user, sizeof(ctx.user), "%s", config->user);
    ctx.current_diff = 1.0;
    ctx.extranonce2_size = 4;

    /* 2. mining.subscribe */
    const char *sub_msg = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"TMiner/1.0\"]}\n";
    stratum_send(&ctx, sub_msg);

    char recv_buf[16384];
    size_t buf_pos = 0;

    /* Read subscribe response */
    ssize_t n = recv(sock, recv_buf, sizeof(recv_buf) - 1, 0);
    if (n <= 0) {
        fprintf(stderr, "[-] No response to subscribe.\n");
        close(sock);
        return -1;
    }
    recv_buf[n] = '\0';

    char *first_newline = strchr(recv_buf, '\n');
    char first_line[16384] = "";
    if (first_newline) {
        size_t line_len = (size_t)(first_newline - recv_buf);
        if (line_len >= sizeof(first_line)) line_len = sizeof(first_line) - 1;
        memcpy(first_line, recv_buf, line_len);
        first_line[line_len] = '\0';
        /* Shift remainder */
        size_t rem = (size_t)(recv_buf + n - (first_newline + 1));
        memmove(recv_buf, first_newline + 1, rem);
        buf_pos = rem;
        recv_buf[buf_pos] = '\0';
    } else {
        snprintf(first_line, sizeof(first_line), "%s", recv_buf);
        buf_pos = 0;
    }

    /* Parse extranonce1 and extranonce2_size from first_line */
    const char *r = strstr(first_line, "\"result\":");
    if (r) {
        const char *id_part = strstr(r, "],\"id\"");
        if (id_part) {
            const char *p = id_part;
            while (p > r && *p != ',') p--;
            if (*p == ',') {
                ctx.extranonce2_size = atoi(p + 1);
                const char *q_end = p;
                while (q_end > r && *q_end != '\"') q_end--;
                if (*q_end == '\"') {
                    const char *q_start = q_end - 1;
                    while (q_start > r && *q_start != '\"') q_start--;
                    if (*q_start == '\"') {
                        size_t len = (size_t)(q_end - q_start - 1);
                        if (len < sizeof(ctx.extranonce1_hex)) {
                            memcpy(ctx.extranonce1_hex, q_start + 1, len);
                            ctx.extranonce1_hex[len] = '\0';
                        }
                    }
                }
            }
        }
    }
    printf("[*] Extranonce1: %s | Extranonce2 size: %d\n", ctx.extranonce1_hex, ctx.extranonce2_size);

    /* 3. mining.authorize */
    char auth_msg[512];
    snprintf(auth_msg, sizeof(auth_msg),
             "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}\n",
             config->user, config->pass);
    stratum_send(&ctx, auth_msg);

    /* 4. Start Mining Threads */
    pthread_t *worker_threads = malloc(sizeof(pthread_t) * ctx.num_threads);
    stratum_worker_t *workers = malloc(sizeof(stratum_worker_t) * ctx.num_threads);

    for (int i = 0; i < ctx.num_threads; i++) {
        workers[i].thread_id = i;
        workers[i].ctx = &ctx;
        pthread_create(&worker_threads[i], NULL, stratum_mining_worker, &workers[i]);
    }

    /* 5. Main Network Loop */
    double start_time = get_time_sec();
    double last_status_time = start_time;

    /* Process any remaining lines from the initial handshake */
    if (buf_pos > 0) {
        char *line_start = recv_buf;
        char *line_end;
        while ((line_end = strchr(line_start, '\n')) != NULL) {
            *line_end = '\0';
            handle_stratum_message(&ctx, line_start);
            line_start = line_end + 1;
        }
        size_t remaining = (size_t)(recv_buf + buf_pos - line_start);
        if (remaining > 0 && line_start != recv_buf) {
            memmove(recv_buf, line_start, remaining);
        }
        buf_pos = remaining;
    }

    while (g_running) {
        /* Set socket read timeout to 1 second for responsive dashboard */
        struct timeval tv = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        ssize_t bytes_read = recv(sock, recv_buf + buf_pos, sizeof(recv_buf) - buf_pos - 1, 0);
        if (bytes_read > 0) {
            buf_pos += (size_t)bytes_read;
            recv_buf[buf_pos] = '\0';

            char *line_start = recv_buf;
            char *line_end;
            while ((line_end = strchr(line_start, '\n')) != NULL) {
                *line_end = '\0';
                handle_stratum_message(&ctx, line_start);
                line_start = line_end + 1;
            }

            size_t remaining = (size_t)(recv_buf + buf_pos - line_start);
            if (remaining > 0 && line_start != recv_buf) {
                memmove(recv_buf, line_start, remaining);
            }
            buf_pos = remaining;
        }

        /* Periodic live status update */
        double now = get_time_sec();
        if (now - last_status_time >= 1.0) {
            last_status_time = now;
            double elapsed = now - start_time;
            uint64_t hashes = atomic_load(&ctx.total_hashes);
            double rate = (elapsed > 0) ? ((double)hashes / elapsed) : 0;
            uint32_t acc = (uint32_t)atomic_load(&ctx.shares_accepted);
            uint32_t rej = (uint32_t)atomic_load(&ctx.shares_rejected);
            uint32_t blk = (uint32_t)atomic_load(&ctx.blocks_found);

            printf(ANSI_COLOR_YELLOW
                   "\r[Stratum] Up: %02d:%02d:%02d | Rate: %.2f MH/s | Shares: %u Acc / %u Rej | Blocks: %u"
                   ANSI_COLOR_RESET "  ",
                   (int)elapsed / 3600, ((int)elapsed % 3600) / 60, (int)elapsed % 60,
                   rate / 1e6, acc, rej, blk);
            fflush(stdout);
        }
    }

    printf("\n\n" ANSI_COLOR_CYAN "[*] Shutting down miner gracefully..." ANSI_COLOR_RESET "\n");
    atomic_store(&ctx.stop_workers, true);

    for (int i = 0; i < ctx.num_threads; i++) {
        pthread_join(worker_threads[i], NULL);
    }

    free(worker_threads);
    free(workers);
    close(sock);
    pthread_mutex_destroy(&ctx.sock_mutex);
    pthread_mutex_destroy(&ctx.job_mutex);

    double total_time = get_time_sec() - start_time;
    uint64_t final_hashes = atomic_load(&ctx.total_hashes);
    printf("\n--- Mining Session Summary ---\n");
    printf("  Duration:        %.1f seconds\n", total_time);
    printf("  Total Hashes:    %lu\n", (unsigned long)final_hashes);
    printf("  Average Rate:    %.2f MH/s\n", (total_time > 0) ? (final_hashes / total_time / 1e6) : 0);
    printf("  Shares Accepted: %lu\n", (unsigned long)atomic_load(&ctx.shares_accepted));
    printf("  Shares Rejected: %lu\n", (unsigned long)atomic_load(&ctx.shares_rejected));
    printf("  Blocks Found:    %lu\n\n", (unsigned long)atomic_load(&ctx.blocks_found));

    return 0;
}
