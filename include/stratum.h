#ifndef STRATUM_H
#define STRATUM_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char host[256];
    int  port;
    char user[256];      /* Bitcoin address or username.worker */
    char pass[128];      /* Password (usually "x") */
    int  num_threads;    /* Mining threads */
} stratum_config_t;

/* Stratum V1 mining client */
int stratum_mine(const stratum_config_t *config);

#endif
