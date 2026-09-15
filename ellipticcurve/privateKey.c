#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "secp256k1.h"

#define PEM_LABEL "EC PRIVATE KEY"

/* A secret is valid in [1, n-1]: zero has no inverse, n and above wrap. */
static int secretInRange(const unsigned char *secret)
{
    if (starkecdsaIsZeroBytes(secret, STARKECDSA_SECRET_BYTES)) {
        return 0;
    }
    return starkecdsaCompareBytes(secret, starkecdsaCurveOrder, STARKECDSA_SECRET_BYTES) < 0;
}

static int fromSecret(const unsigned char *secret, starkecdsa_private_key **out)
{
    starkecdsa_private_key *key;

    if (!secretInRange(secret)) {
        return STARKECDSA_ERROR_RANGE;
    }
    if (!secp256k1_ec_seckey_verify((const secp256k1_context *)starkecdsaContext(), secret)) {
        return STARKECDSA_ERROR_RANGE;
    }
    key = (starkecdsa_private_key *)malloc(sizeof(*key));
    if (key == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    memcpy(key->secret, secret, STARKECDSA_SECRET_BYTES);
    *out = key;
    return STARKECDSA_OK;
}

int starkecdsa_private_key_new(starkecdsa_private_key **out)
{
    unsigned char secret[STARKECDSA_SECRET_BYTES];
    int attempts = 0;

    if (out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    /* Rejection sampling: a draw at or above the order is discarded rather
       than reduced, which would bias the low end of the range. */
    for (attempts = 0; attempts < 64; attempts++) {
        int status = starkecdsaRandomBytes(secret, sizeof(secret));
        if (status != STARKECDSA_OK) {
            return status;
        }
        if (secretInRange(secret)) {
            status = fromSecret(secret, out);
            memset(secret, 0, sizeof(secret));
            return status;
        }
    }
    memset(secret, 0, sizeof(secret));
    return STARKECDSA_ERROR_ENTROPY;
}

int starkecdsa_private_key_from_string(const char *hex, starkecdsa_private_key **out)
{
    unsigned char secret[STARKECDSA_SECRET_BYTES];
    int status;

    if (hex == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsaBytesFromHex(hex, secret, STARKECDSA_SECRET_BYTES);
    if (status != STARKECDSA_OK) {
        return status;
    }
    status = fromSecret(secret, out);
    memset(secret, 0, sizeof(secret));
    return status;
}

int starkecdsa_private_key_from_der(const unsigned char *der, size_t der_len, starkecdsa_private_key **out)
{
    unsigned char secret[STARKECDSA_SECRET_BYTES];
    unsigned char storedPoint[STARKECDSA_POINT_BYTES];
    int hasPoint = 0;
    int status;

    if (der == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsaDerReadPrivateKey(der, der_len, secret, storedPoint, &hasPoint);
    if (status != STARKECDSA_OK) {
        memset(secret, 0, sizeof(secret));
        return status;
    }
    status = fromSecret(secret, out);
    memset(secret, 0, sizeof(secret));
    if (status != STARKECDSA_OK) {
        return status;
    }

    /* The file carries the public key too. If it disagrees with the one the
       secret derives, the file is inconsistent and we refuse it rather than
       silently trusting the secret. */
    if (hasPoint) {
        starkecdsa_public_key *derived = NULL;
        status = starkecdsa_private_key_public_key(*out, &derived);
        if (status != STARKECDSA_OK) {
            starkecdsa_private_key_free(*out);
            *out = NULL;
            return status;
        }
        if (memcmp(derived->point, storedPoint, STARKECDSA_POINT_BYTES) != 0) {
            starkecdsa_public_key_free(derived);
            starkecdsa_private_key_free(*out);
            *out = NULL;
            return STARKECDSA_ERROR_KEY_PAIR;
        }
        starkecdsa_public_key_free(derived);
    }
    return STARKECDSA_OK;
}

int starkecdsa_private_key_from_pem(const char *pem, starkecdsa_private_key **out)
{
    unsigned char *der = NULL;
    size_t derLength = 0;
    int status;

    if (pem == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsaPemRead(pem, PEM_LABEL, &der, &derLength);
    if (status != STARKECDSA_OK) {
        return status;
    }
    status = starkecdsa_private_key_from_der(der, derLength, out);
    free(der);
    return status;
}

int starkecdsa_private_key_to_string(const starkecdsa_private_key *key, char **out)
{
    if (key == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    return starkecdsaAllocHexFromBytes(key->secret, STARKECDSA_SECRET_BYTES, out);
}

int starkecdsa_private_key_to_der(const starkecdsa_private_key *key, unsigned char **out, size_t *out_len)
{
    starkecdsa_public_key *publicKey = NULL;
    int status;

    if (key == NULL || out == NULL || out_len == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsa_private_key_public_key(key, &publicKey);
    if (status != STARKECDSA_OK) {
        return status;
    }
    status = starkecdsaDerWritePrivateKey(key->secret, publicKey->point, out, out_len);
    starkecdsa_public_key_free(publicKey);
    return status;
}

int starkecdsa_private_key_to_pem(const starkecdsa_private_key *key, char **out)
{
    unsigned char *der = NULL;
    size_t derLength = 0;
    int status;

    if (key == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsa_private_key_to_der(key, &der, &derLength);
    if (status != STARKECDSA_OK) {
        return status;
    }
    status = starkecdsaPemWrite(PEM_LABEL, der, derLength, out);
    free(der);
    return status;
}

int starkecdsa_private_key_public_key(const starkecdsa_private_key *key, starkecdsa_public_key **out)
{
    const secp256k1_context *ctx = (const secp256k1_context *)starkecdsaContext();
    secp256k1_pubkey pubkey;
    unsigned char serialized[65];
    size_t serializedLength = sizeof(serialized);
    starkecdsa_public_key *result;

    if (key == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (ctx == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key->secret)) {
        return STARKECDSA_ERROR_INTERNAL;
    }
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized, &serializedLength, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        return STARKECDSA_ERROR_INTERNAL;
    }
    if (serializedLength != 65 || serialized[0] != 0x04) {
        return STARKECDSA_ERROR_INTERNAL;
    }
    result = (starkecdsa_public_key *)malloc(sizeof(*result));
    if (result == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    memcpy(result->point, serialized + 1, STARKECDSA_POINT_BYTES);
    *out = result;
    return STARKECDSA_OK;
}

void starkecdsa_private_key_free(starkecdsa_private_key *key)
{
    if (key == NULL) {
        return;
    }
    memset(key->secret, 0, STARKECDSA_SECRET_BYTES);
    free(key);
}
