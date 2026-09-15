#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "secp256k1.h"

#define PEM_LABEL "PUBLIC KEY"

/*
 * Every entry point that builds a public key goes through here, so a point
 * that is not on the curve is rejected once, in one place. Accepting an
 * off-curve point would make verification meaningless.
 */
static int fromPoint(const unsigned char *point, starkecdsa_public_key **out)
{
    const secp256k1_context *ctx = (const secp256k1_context *)starkecdsaContext();
    unsigned char serialized[65];
    secp256k1_pubkey pubkey;
    starkecdsa_public_key *key;

    if (ctx == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    serialized[0] = 0x04;
    memcpy(serialized + 1, point, STARKECDSA_POINT_BYTES);
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, serialized, sizeof(serialized))) {
        return STARKECDSA_ERROR_CURVE;
    }
    key = (starkecdsa_public_key *)malloc(sizeof(*key));
    if (key == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    memcpy(key->point, point, STARKECDSA_POINT_BYTES);
    *out = key;
    return STARKECDSA_OK;
}

int starkecdsa_public_key_from_string(const char *hex, starkecdsa_public_key **out)
{
    unsigned char point[STARKECDSA_POINT_BYTES];
    const char *cursor;
    int status;

    if (hex == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    cursor = hex;
    /* The sibling libraries print the encoded form as "0004" + X + Y. */
    if (strlen(cursor) == STARKECDSA_POINT_BYTES * 2 + 4 && strncmp(cursor, "0004", 4) == 0) {
        cursor += 4;
    }
    if (strlen(cursor) != STARKECDSA_POINT_BYTES * 2) {
        return STARKECDSA_ERROR_ENCODING;
    }
    status = starkecdsaBytesFromHex(cursor, point, STARKECDSA_POINT_BYTES);
    if (status != STARKECDSA_OK) {
        return status;
    }
    return fromPoint(point, out);
}

int starkecdsa_public_key_from_compressed(const char *hex, starkecdsa_public_key **out)
{
    const secp256k1_context *ctx = (const secp256k1_context *)starkecdsaContext();
    unsigned char compressed[33];
    unsigned char serialized[65];
    size_t serializedLength = sizeof(serialized);
    secp256k1_pubkey pubkey;
    int status;

    if (hex == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (ctx == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    if (strlen(hex) != sizeof(compressed) * 2) {
        return STARKECDSA_ERROR_ENCODING;
    }
    status = starkecdsaBytesFromHex(hex, compressed, sizeof(compressed));
    if (status != STARKECDSA_OK) {
        return status;
    }
    if (compressed[0] != 0x02 && compressed[0] != 0x03) {
        return STARKECDSA_ERROR_ENCODING;
    }
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed, sizeof(compressed))) {
        return STARKECDSA_ERROR_CURVE;
    }
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized, &serializedLength, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        return STARKECDSA_ERROR_INTERNAL;
    }
    return fromPoint(serialized + 1, out);
}

int starkecdsa_public_key_from_der(const unsigned char *der, size_t der_len, starkecdsa_public_key **out)
{
    unsigned char point[STARKECDSA_POINT_BYTES];
    int status;

    if (der == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsaDerReadPublicKey(der, der_len, point);
    if (status != STARKECDSA_OK) {
        return status;
    }
    return fromPoint(point, out);
}

int starkecdsa_public_key_from_pem(const char *pem, starkecdsa_public_key **out)
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
    status = starkecdsa_public_key_from_der(der, derLength, out);
    free(der);
    return status;
}

int starkecdsa_public_key_to_string(const starkecdsa_public_key *key, char **out)
{
    if (key == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    return starkecdsaAllocHexFromBytes(key->point, STARKECDSA_POINT_BYTES, out);
}

int starkecdsa_public_key_to_compressed(const starkecdsa_public_key *key, char **out)
{
    const secp256k1_context *ctx = (const secp256k1_context *)starkecdsaContext();
    unsigned char uncompressed[65];
    unsigned char compressed[33];
    size_t compressedLength = sizeof(compressed);
    secp256k1_pubkey pubkey;

    if (key == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (ctx == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    uncompressed[0] = 0x04;
    memcpy(uncompressed + 1, key->point, STARKECDSA_POINT_BYTES);
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, uncompressed, sizeof(uncompressed))) {
        return STARKECDSA_ERROR_CURVE;
    }
    if (!secp256k1_ec_pubkey_serialize(ctx, compressed, &compressedLength, &pubkey, SECP256K1_EC_COMPRESSED)) {
        return STARKECDSA_ERROR_INTERNAL;
    }
    return starkecdsaAllocHexFromBytes(compressed, compressedLength, out);
}

int starkecdsa_public_key_to_der(const starkecdsa_public_key *key, unsigned char **out, size_t *out_len)
{
    if (key == NULL || out == NULL || out_len == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    return starkecdsaDerWritePublicKey(key->point, out, out_len);
}

int starkecdsa_public_key_to_pem(const starkecdsa_public_key *key, char **out)
{
    unsigned char *der = NULL;
    size_t derLength = 0;
    int status;

    if (key == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsa_public_key_to_der(key, &der, &derLength);
    if (status != STARKECDSA_OK) {
        return status;
    }
    status = starkecdsaPemWrite(PEM_LABEL, der, derLength, out);
    free(der);
    return status;
}

void starkecdsa_public_key_free(starkecdsa_public_key *key)
{
    free(key);
}
