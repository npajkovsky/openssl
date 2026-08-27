/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/names.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn digest_gettable_params;
static OSSL_FUNC_provider_get_params_fn digest_get_params;
static OSSL_FUNC_provider_query_operation_fn digest_query;

/* Parameters we provide to the core */
static const OSSL_PARAM digest_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digest_gettable_params(void *provctx)
{
    return digest_param_types;
}

static int digest_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Digest Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

/*
 * For the algorithm names, we use the following formula for our primary
 * names:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD2, MD4, MD5).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 *
 * We add diverse other names where applicable, such as the names that
 * NIST uses, or that are used for ASN.1 OBJECT IDENTIFIERs, or names
 * we have used historically.
 *
 * Algorithm names are case insensitive, but we use all caps in our "canonical"
 * names for consistency.
 */
static const OSSL_ALGORITHM digest_digests[] = {
    /* Our primary name:NIST name[:our older names] */
    { PROV_NAMES_SHA1, "provider=digest", ossl_sha1_functions },
    { PROV_NAMES_SHA2_224, "provider=digest", ossl_sha224_functions },
    { PROV_NAMES_SHA2_256, "provider=digest", ossl_sha256_functions },
    { PROV_NAMES_SHA2_256_192, "provider=digest", ossl_sha256_192_internal_functions },
    { PROV_NAMES_SHA2_384, "provider=digest", ossl_sha384_functions },
    { PROV_NAMES_SHA2_512, "provider=digest", ossl_sha512_functions },
    { PROV_NAMES_SHA2_512_224, "provider=digest", ossl_sha512_224_functions },
    { PROV_NAMES_SHA2_512_256, "provider=digest", ossl_sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { PROV_NAMES_SHA3_224, "provider=digest", ossl_sha3_224_functions },
    { PROV_NAMES_SHA3_256, "provider=digest", ossl_sha3_256_functions },
    { PROV_NAMES_SHA3_384, "provider=digest", ossl_sha3_384_functions },
    { PROV_NAMES_SHA3_512, "provider=digest", ossl_sha3_512_functions },

    { PROV_NAMES_KECCAK_224, "provider=digest", ossl_keccak_224_functions },
    { PROV_NAMES_KECCAK_256, "provider=digest", ossl_keccak_256_functions },
    { PROV_NAMES_KECCAK_384, "provider=digest", ossl_keccak_384_functions },
    { PROV_NAMES_KECCAK_512, "provider=digest", ossl_keccak_512_functions },

    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * the KMAC-128 and KMAC-256.
     */
    { PROV_NAMES_CSHAKE_KECCAK_128, "provider=digest",
        ossl_cshake_keccak_128_functions },
    { PROV_NAMES_CSHAKE_KECCAK_256, "provider=digest",
        ossl_cshake_keccak_256_functions },

    /* Our primary name:NIST name */
    { PROV_NAMES_SHAKE_128, "provider=digest", ossl_shake_128_functions },
    { PROV_NAMES_SHAKE_256, "provider=digest", ossl_shake_256_functions },

    { PROV_NAMES_CSHAKE_128, "provider=digest", ossl_cshake_128_functions },
    { PROV_NAMES_CSHAKE_256, "provider=digest", ossl_cshake_256_functions },

#ifndef OPENSSL_NO_BLAKE2
    /*
     * https://blake2.net/ doesn't specify size variants,
     * but mentions that Bouncy Castle uses the names
     * BLAKE2b-160, BLAKE2b-256, BLAKE2b-384, and BLAKE2b-512
     * If we assume that "2b" and "2s" are versions, that pattern
     * fits with ours.  We also add our historical names.
     */
    { PROV_NAMES_BLAKE2S_256, "provider=digest", ossl_blake2s256_functions },
    { PROV_NAMES_BLAKE2B_512, "provider=digest", ossl_blake2b512_functions },
#endif /* OPENSSL_NO_BLAKE2 */

#ifndef OPENSSL_NO_SM3
    { PROV_NAMES_SM3, "provider=digest", ossl_sm3_functions },
#endif /* OPENSSL_NO_SM3 */

#ifndef OPENSSL_NO_MD5
    { PROV_NAMES_MD5, "provider=digest", ossl_md5_functions },
    { PROV_NAMES_MD5_SHA1, "provider=digest", ossl_md5_sha1_functions },
#endif /* OPENSSL_NO_MD5 */

#ifndef OPENSSL_NO_RMD160
    { PROV_NAMES_RIPEMD_160, "provider=digest", ossl_ripemd160_functions },
#endif /* OPENSSL_NO_RMD160 */

    { PROV_NAMES_NULL, "provider=digest", ossl_nullmd_functions },
#ifndef OPENSSL_NO_ML_DSA
    { PROV_NAMES_ML_DSA_MU, "provider=digest", ossl_ml_dsa_mu_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *digest_query(void *provctx, int operation_id,
    int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return digest_digests;
    }
    return NULL;
}

static void digest_teardown(void *provctx)
{
    ossl_prov_ctx_free(provctx);
}

/* Functions we provide to the core */
static const OSSL_DISPATCH digest_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))digest_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))digest_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))digest_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))digest_query },
    OSSL_DISPATCH_END
};

OSSL_provider_init_fn ossl_digest_provider_init;

int ossl_digest_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx)
{
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along in the provider context.
     *
     * This only works for built-in providers.  Most providers should
     * create their own library context.
     */
    if ((*provctx = ossl_prov_ctx_new()) == NULL)
        return 0;
    ossl_prov_ctx_set0_libctx(*provctx,
        (OSSL_LIB_CTX *)c_get_libctx(handle));
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_core_get_params(*provctx, c_get_params);

    *out = digest_dispatch_table;

    return 1;
}
