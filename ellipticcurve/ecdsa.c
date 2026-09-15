#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "secp256k1.h"
#include "secp256k1_recovery.h"

/*
 * Signing follows the same hedged RFC 6979 the other Stark libraries use:
 * the nonce is derived deterministically from the key and the message, with
 * fresh system entropy mixed into the derivation as RFC 6979 section 3.6
 * allows. That keeps two properties at once -- a broken system RNG cannot
 * produce a repeated nonce, and a repeated message does not produce a
 * repeated signature.
 *
 * libsecp256k1's default nonce function is exactly this construction, and its
 * ndata argument is the extra-entropy input. It also normalizes s into the
 * lower half of the range and reports the recovery id, so the signature shape
 * matches what the Digital-Signature header expects without any arithmetic
 * here.
 */

int starkecdsa_sign(const unsigned char *message, size_t message_len,
                    const starkecdsa_private_key *key, starkecdsa_signature **out)
{
    const secp256k1_context *ctx = (const secp256k1_context *)starkecdsaContext();
    unsigned char digest[STARKECDSA_SHA256_BYTES];
    unsigned char entropy[32];
    secp256k1_ecdsa_recoverable_signature recoverable;
    unsigned char compact[64];
    starkecdsa_signature *signature;
    int recoveryId = 0;
    int status;

    if (key == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (message == NULL && message_len > 0) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (out != NULL) {
        *out = NULL;
    }
    if (ctx == NULL) {
        return STARKECDSA_ERROR_ENTROPY;
    }

    starkecdsaSha256(message, message_len, digest);

    status = starkecdsaRandomBytes(entropy, sizeof(entropy));
    if (status != STARKECDSA_OK) {
        starkecdsaScrub(digest, sizeof(digest));
        return status;
    }

    if (!secp256k1_ecdsa_sign_recoverable(ctx, &recoverable, digest, key->secret,
                                          secp256k1_nonce_function_rfc6979, entropy)) {
        starkecdsaScrub(digest, sizeof(digest));
        starkecdsaScrub(entropy, sizeof(entropy));
        return STARKECDSA_ERROR_INTERNAL;
    }
    starkecdsaScrub(entropy, sizeof(entropy));
    starkecdsaScrub(digest, sizeof(digest));

    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, compact, &recoveryId, &recoverable)) {
        return STARKECDSA_ERROR_INTERNAL;
    }

    signature = (starkecdsa_signature *)malloc(sizeof(*signature));
    if (signature == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    memcpy(signature->r, compact, STARKECDSA_SECRET_BYTES);
    memcpy(signature->s, compact + STARKECDSA_SECRET_BYTES, STARKECDSA_SECRET_BYTES);
    signature->recoveryId = recoveryId;
    *out = signature;
    return STARKECDSA_OK;
}

int starkecdsa_verify(const unsigned char *message, size_t message_len,
                      const starkecdsa_signature *signature, const starkecdsa_public_key *key)
{
    const secp256k1_context *ctx = (const secp256k1_context *)starkecdsaContext();
    unsigned char digest[STARKECDSA_SHA256_BYTES];
    unsigned char serialized[65];
    unsigned char compact[64];
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature parsed;
    secp256k1_ecdsa_signature normalized;

    if (signature == NULL || key == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (message == NULL && message_len > 0) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (ctx == NULL) {
        return STARKECDSA_ERROR_ENTROPY;
    }

    memcpy(compact, signature->r, STARKECDSA_SECRET_BYTES);
    memcpy(compact + STARKECDSA_SECRET_BYTES, signature->s, STARKECDSA_SECRET_BYTES);
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &parsed, compact)) {
        return STARKECDSA_ERROR_RANGE;
    }

    /*
     * libsecp256k1 refuses a signature whose s sits in the upper half, to keep
     * signatures non-malleable. OpenSSL and other producers do not normalize,
     * and ECDSA verification is unchanged by replacing s with n - s, so
     * normalizing here accepts those signatures without weakening the check.
     */
    secp256k1_ecdsa_signature_normalize(ctx, &normalized, &parsed);

    serialized[0] = 0x04;
    memcpy(serialized + 1, key->point, STARKECDSA_POINT_BYTES);
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, serialized, sizeof(serialized))) {
        return STARKECDSA_ERROR_CURVE;
    }

    starkecdsaSha256(message, message_len, digest);

    if (!secp256k1_ecdsa_verify(ctx, &normalized, digest, &pubkey)) {
        starkecdsaScrub(digest, sizeof(digest));
        return STARKECDSA_ERROR_RANGE;
    }
    starkecdsaScrub(digest, sizeof(digest));
    return STARKECDSA_OK;
}
