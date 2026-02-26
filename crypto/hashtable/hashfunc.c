/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 */

#include "internal/hashfunc.h"

ossl_unused uint64_t ossl_fnv1a_hash_init(void)
{
    return 0xcbf29ce484222325ULL;
}

ossl_unused uint64_t ossl_fnv1a_hash_update(uint64_t hash, const uint8_t *key,
    size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= key[i];
        hash *= 0x00000100000001B3ULL;
    }
    return hash;
}

ossl_unused uint64_t ossl_fnv1a_hash(uint8_t *key, size_t len)
{
    return ossl_fnv1a_hash_update(ossl_fnv1a_hash_init(), key, len);
}
