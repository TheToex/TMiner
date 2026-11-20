#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "tminer.h"
#include "sha256.h"
#include "stratum.h"

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [options]\n\n", prog_name);
    printf("Pool Mining Options (Real Bitcoin Network via Stratum):\n");
    printf("  -o, --pool <host>       Stratum mining pool hostname/IP (e.g. solo.ckpool.org)\n");
    printf("  -p, --port <port>       Stratum mining pool port (default: 3333)\n");
    printf("  -u, --user <wallet>     Bitcoin wallet address or worker name\n");
    printf("  -w, --pass <pass>       Worker password (default: x)\n\n");
    printf("Standalone / Demo Mining Options:\n");
    printf("  -s, --string <text>     Mine a custom string/payload\n");
    printf("  -d, --diff <zeros>      Difficulty (number of leading hex zeros, default: 4)\n");
    printf("  -g, --genesis           Mine Bitcoin Genesis block header (starts near nonce for demo)\n");
    printf("  -G, --genesis-full      Mine Bitcoin Genesis block header starting from nonce 0\n");
    printf("  -S, --sample            Mine Bitcoin Block #125552 header\n");
    printf("  -t, --threads <n>       Number of CPU mining threads (default: CPU cores)\n");
    printf("  -n, --start-nonce <n>   Starting nonce (default: 0)\n");
    printf("  -m, --max-nonce <n>     Maximum nonce (default: UINT32_MAX)\n");
    printf("  -b, --benchmark         Run CPU Double-SHA256 hashrate benchmark\n");
    printf("  -h, --help              Show this help message\n\n");
    printf("Examples:\n");
    printf("  # Mine real Bitcoin on Solo CKPool (rewards sent directly to your wallet):\n");
    printf("  %s --pool solo.ckpool.org --port 3333 --user <YOUR_BITCOIN_WALLET_ADDRESS>\n\n", prog_name);
    printf("  # Local string mining demo:\n");
    printf("  %s --string \"TMiner Block\" --diff 5\n\n", prog_name);
    printf("  # CPU Hashrate benchmark:\n");
    printf("  %s --benchmark --threads 8\n", prog_name);
}

int main(int argc, char *argv[])
{
    tminer_init();

    int num_threads = 0;
    int hex_zeros = 4;
    uint32_t start_nonce = 0;
    uint32_t max_nonce = 0xffffffffU;
    const char *custom_string = NULL;
    int mode_genesis = 0;
    int mode_genesis_full = 0;
    int mode_sample = 0;
    int mode_benchmark = 0;

    char pool_host[256] = "";
    int pool_port = 3333;
    char pool_user[256] = "";
    char pool_pass[128] = "x";

    static struct option long_options[] = {
        {"pool",         required_argument, 0, 'o'},
        {"port",         required_argument, 0, 'p'},
        {"user",         required_argument, 0, 'u'},
        {"pass",         required_argument, 0, 'w'},
        {"string",       required_argument, 0, 's'},
        {"diff",         required_argument, 0, 'd'},
        {"genesis",      no_argument,       0, 'g'},
        {"genesis-full", no_argument,       0, 'G'},
        {"sample",       no_argument,       0, 'S'},
        {"threads",      required_argument, 0, 't'},
        {"start-nonce",  required_argument, 0, 'n'},
        {"max-nonce",    required_argument, 0, 'm'},
        {"benchmark",    no_argument,       0, 'b'},
        {"help",         no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "o:p:u:w:s:d:gGSt:n:m:bh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'o': {
                /* Strip stratum+tcp:// if user supplied it */
                const char *h = optarg;
                if (strncmp(h, "stratum+tcp://", 14) == 0) h += 14;
                else if (strncmp(h, "tcp://", 6) == 0) h += 6;
                char *colon = strchr(h, ':');
                if (colon) {
                    size_t hlen = (size_t)(colon - h);
                    if (hlen >= sizeof(pool_host)) hlen = sizeof(pool_host) - 1;
                    memcpy(pool_host, h, hlen);
                    pool_host[hlen] = '\0';
                    pool_port = atoi(colon + 1);
                } else {
                    strncpy(pool_host, h, sizeof(pool_host) - 1);
                }
                break;
            }
            case 'p':
                pool_port = atoi(optarg);
                break;
            case 'u':
                strncpy(pool_user, optarg, sizeof(pool_user) - 1);
                break;
            case 'w':
                strncpy(pool_pass, optarg, sizeof(pool_pass) - 1);
                break;
            case 's':
                custom_string = optarg;
                break;
            case 'd':
                hex_zeros = atoi(optarg);
                break;
            case 'g':
                mode_genesis = 1;
                break;
            case 'G':
                mode_genesis_full = 1;
                break;
            case 'S':
                mode_sample = 1;
                break;
            case 't':
                num_threads = atoi(optarg);
                break;
            case 'n':
                start_nonce = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'm':
                max_nonce = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'b':
                mode_benchmark = 1;
                break;
            case 'h':
            default:
                tminer_print_banner();
                print_usage(argv[0]);
                return 0;
        }
    }

    tminer_print_banner();

    /* Mode: Stratum Pool Mining */
    if (pool_host[0] != '\0') {
        if (pool_user[0] == '\0') {
            fprintf(stderr, "Error: Pool username/wallet address (-u / --user) is required for pool mining.\n");
            fprintf(stderr, "Example: %s --pool solo.ckpool.org --user <Your_BTC_Address>\n", argv[0]);
            return 1;
        }
        stratum_config_t s_cfg;
        memset(&s_cfg, 0, sizeof(s_cfg));
        snprintf(s_cfg.host, sizeof(s_cfg.host), "%s", pool_host);
        s_cfg.port = (pool_port > 0) ? pool_port : 3333;
        snprintf(s_cfg.user, sizeof(s_cfg.user), "%s", pool_user);
        snprintf(s_cfg.pass, sizeof(s_cfg.pass), "%s", pool_pass);
        s_cfg.num_threads = num_threads;

        return stratum_mine(&s_cfg);
    }

    tminer_result_t result;

    if (mode_benchmark) {
        tminer_benchmark(num_threads, 3.0);
        return 0;
    }

    if (mode_genesis) {
        bitcoin_block_header_t hdr;
        get_genesis_block(&hdr);
        uint32_t demo_start = (hdr.nonce > 500000) ? (hdr.nonce - 500000) : 0;
        printf("[*] Mining Bitcoin Genesis Block (demo window starting at %u)...\n", demo_start);
        return tminer_mine_block(&hdr, demo_start, max_nonce, num_threads, &result);
    }

    if (mode_genesis_full) {
        bitcoin_block_header_t hdr;
        get_genesis_block(&hdr);
        printf("[*] Mining Bitcoin Genesis Block from Nonce 0...\n");
        return tminer_mine_block(&hdr, 0, max_nonce, num_threads, &result);
    }

    if (mode_sample) {
        bitcoin_block_header_t hdr;
        get_sample_block(&hdr);
        uint32_t demo_start = (hdr.nonce > 500000) ? (hdr.nonce - 500000) : 0;
        printf("[*] Mining Bitcoin Block #125552 (demo window starting at %u)...\n", demo_start);
        return tminer_mine_block(&hdr, demo_start, max_nonce, num_threads, &result);
    }

    if (custom_string) {
        return tminer_mine_string(custom_string, hex_zeros, start_nonce, max_nonce, num_threads, &result);
    }

    /* Default demo if no arguments provided */
    printf("[i] No arguments supplied. Running quick interactive demonstration:\n\n");
    tminer_mine_string("TMiner-Block-", 5, 0, 5000000, num_threads, &result);

    printf("\nTip: Run '%s --help' to see pool mining and standalone options.\n", argv[0]);
    return 0;
}
