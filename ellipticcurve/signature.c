#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "secp256k1.h"

/*
 * r and s are stored exactly as they arrived, never normalized on the way in.
 * That matters for round-tripping: a signature produced by OpenSSL may carry
 * an s in the upper half of the range, and rewriting it to the lower half
 * would still verify but would no longer reproduce the bytes we were handed.
 * Normalization happens transiently inside verify instead.
 */

int starkecdsa_signature_to_der(const starkecdsa_signature *signature, int with_recovery_id,
                                unsigned char **out, size_t *out_len)
{
    const secp256k1_context *ctx = (const secp256k1_context *)starkecdsaContext();
    secp256k1_ecdsa_signature parsed;
    unsigned char compact[64];
    unsigned char encoded[80];
    size_t encodedLength = sizeof(encoded);
    unsigned char *buffer;
    size_t offset = 0;

    if (signature == NULL || out == NULL || out_len == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (ctx == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    if (with_recovery_id && (signature->recoveryId < 0 || signature->recoveryId > 3)) {
        return STARKECDSA_ERROR_RANGE;
    }

    memcpy(compact, signature->r, STARKECDSA_SECRET_BYTES);
    memcpy(compact + STARKECDSA_SECRET_BYTES, signature->s, STARKECDSA_SECRET_BYTES);
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &parsed, compact)) {
        return STARKECDSA_ERROR_RANGE;
    }
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, encoded, &encodedLength, &parsed)) {
        return STARKECDSA_ERROR_INTERNAL;
    }

    buffer = (unsigned char *)malloc(encodedLength + 1);
    if (buffer == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    if (with_recovery_id) {
        buffer[offset++] = (unsigned char)(27 + signature->recoveryId);
    }
    memcpy(buffer + offset, encoded, encodedLength);
    *out = buffer;
    *out_len = offset + encodedLength;
    return STARKECDSA_OK;
}

int starkecdsa_signature_from_der(const unsigned char *der, size_t der_len, int with_recovery_id,
                                  starkecdsa_signature **out)
{
    const secp256k1_context *ctx = (const secp256k1_context *)starkecdsaContext();
    secp256k1_ecdsa_signature parsed;
    unsigned char compact[64];
    starkecdsa_signature *signature;
    int recoveryId = -1;

    if (der == NULL || out == NULL || der_len == 0) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (ctx == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }

    if (with_recovery_id) {
        if (der[0] < 27 || der[0] > 30) {
            return STARKECDSA_ERROR_ENCODING;
        }
        recoveryId = der[0] - 27;
        der += 1;
        der_len -= 1;
        if (der_len == 0) {
            return STARKECDSA_ERROR_ENCODING;
        }
    }

    if (!secp256k1_ecdsa_signature_parse_der(ctx, &parsed, der, der_len)) {
        return STARKECDSA_ERROR_ENCODING;
    }
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, compact, &parsed)) {
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

int starkecdsa_signature_to_base64(const starkecdsa_signature *signature, int with_recovery_id, char **out)
{
    unsigned char *der = NULL;
    size_t derLength = 0;
    int status;

    if (signature == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsa_signature_to_der(signature, with_recovery_id, &der, &derLength);
    if (status != STARKECDSA_OK) {
        return status;
    }
    status = starkecdsaBase64FromBytes(der, derLength, out);
    free(der);
    return status;
}

int starkecdsa_signature_from_base64(const char *base64, int with_recovery_id, starkecdsa_signature **out)
{
    unsigned char *der = NULL;
    size_t derLength = 0;
    int status;

    if (base64 == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsaBytesFromBase64(base64, &der, &derLength);
    if (status != STARKECDSA_OK) {
        return status;
    }
    status = starkecdsa_signature_from_der(der, derLength, with_recovery_id, out);
    free(der);
    return status;
}

int starkecdsa_signature_recovery_id(const starkecdsa_signature *signature)
{
    if (signature == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (signature->recoveryId < 0) {
        return STARKECDSA_ERROR_RANGE;
    }
    return signature->recoveryId;
}

void starkecdsa_signature_free(starkecdsa_signature *signature)
{
    free(signature);
}
