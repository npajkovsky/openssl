/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "internal/quic_port.h"
#include "internal/quic_ssl.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/quic/quic_local.h"

#include "testutil.h"

static int fail_qlog_title_alloc;
static int fail_triggered;

static const char qlog_title[] = "QUIC port qlog leak test";

static int is_target_alloc(size_t num, const char *file)
{
    return fail_qlog_title_alloc
        && !fail_triggered
        && num == sizeof(qlog_title)
        && file != NULL
        && strstr(file, "ssl/quic/quic_port.c") != NULL;
}

static void *test_malloc(size_t num, const char *file, int line)
{
    void *m;

    if (num == 0)
        return NULL;

    if (is_target_alloc(num, file)) {
        fail_triggered = 1;
        return NULL;
    }

    m = malloc(num);
    if (m == NULL)
        return NULL;

    return m;
}

static void test_free(void *addr, const char *file, int line)
{
    free(addr);
}

static void *test_realloc(void *addr, size_t num, const char *file, int line)
{
    if (addr == NULL)
        return test_malloc(num, file, line);

    if (is_target_alloc(num, file)) {
        fail_triggered = 1;
        return NULL;
    }

    addr = realloc(addr, num);
    if (addr == NULL)
        return NULL;

    return addr;
}

static int test_incoming_qlog_title_alloc_failure(void)
{
    SSL_CTX *ctx = NULL;
    SSL *listener = NULL;
    QUIC_LISTENER *ql;
    QUIC_CHANNEL *ch = NULL;
    int ok = 0;

    if (!TEST_true(CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free)))
        return 0;

    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(ossl_quic_set_diag_title(ctx, qlog_title)))
        goto err;

    listener = SSL_new_listener(ctx, SSL_LISTENER_FLAG_NO_VALIDATE);
    if (!TEST_ptr(listener))
        goto err;

    ql = QUIC_LISTENER_FROM_SSL(listener);
    if (!TEST_true(ossl_quic_port_test_and_set_peeloff(ql->port, PEELOFF_ACCEPT)))
        goto err;

    fail_qlog_title_alloc = 1;
    ch = ossl_quic_port_create_incoming(ql->port, NULL);
    fail_qlog_title_alloc = 0;
    if (!TEST_ptr_null(ch)
        || !TEST_true(fail_triggered))
        goto err;

    ok = 1;

err:
    ossl_quic_channel_free(ch);
    SSL_free(listener);
    SSL_CTX_free(ctx);
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_incoming_qlog_title_alloc_failure);

    return 1;
}
