/*
 * Just enough DER for the two shapes Stark key files use. This is not a
 * general ASN.1 parser and should not become one: every length is bounded,
 * every tag is checked, every structure must consume exactly its input, and
 * the two SEC1 containers are required rather than optional, because these
 * bytes arrive from disk and the checks they carry are the ones that catch a
 * wrong-curve key or a corrupted key pair.
 *
 * Private key, SEC1 (RFC 5915 marks [0] and [1] OPTIONAL; this library
 * requires both, as the Python reference effectively does):
 *   SEQUENCE { INTEGER 1, OCTET STRING secret,
 *              [0] { OID curve }, [1] { BIT STRING 00 04 X Y } }
 *
 * Public key, SubjectPublicKeyInfo:
 *   SEQUENCE { SEQUENCE { OID ecPublicKey, OID curve },
 *              BIT STRING 00 04 X Y }
 */

#include <stdlib.h>
#include <string.h>
#include "../internal.h"

#define TAG_INTEGER 0x02
#define TAG_BIT_STRING 0x03
#define TAG_OCTET_STRING 0x04
#define TAG_OID 0x06
#define TAG_SEQUENCE 0x30
#define TAG_CONTEXT_0 0xa0
#define TAG_CONTEXT_1 0xa1

/* ------------------------------------------------------------------ reading */

static int readLength(const unsigned char *der, size_t available, size_t *length, size_t *headerBytes)
{
    unsigned char first;
    size_t count;
    size_t value = 0;
    size_t index;

    if (available < 1) {
        return STARKECDSA_ERROR_ENCODING;
    }
    first = der[0];
    if ((first & 0x80u) == 0) {
        *length = first;
        *headerBytes = 1;
        return STARKECDSA_OK;
    }
    count = first & 0x7fu;
    /* Indefinite length and anything wider than a size_t is not DER we emit. */
    if (count == 0 || count > 4 || available < count + 1) {
        return STARKECDSA_ERROR_ENCODING;
    }
    /* DER requires the shortest form: no leading zero byte in a long form ... */
    if (der[1] == 0x00) {
        return STARKECDSA_ERROR_ENCODING;
    }
    for (index = 0; index < count; index++) {
        value = (value << 8) | der[index + 1];
    }
    /* ... and no long form for a value the short form could carry. */
    if (value < 128) {
        return STARKECDSA_ERROR_ENCODING;
    }
    *length = value;
    *headerBytes = count + 1;
    return STARKECDSA_OK;
}

int starkecdsaDerReadTag(const unsigned char *der, size_t available, unsigned char tag,
                         const unsigned char **body, size_t *bodyLength, size_t *consumed)
{
    size_t length = 0;
    size_t headerBytes = 0;
    int status;

    if (der == NULL || available < 2 || der[0] != tag) {
        return STARKECDSA_ERROR_ENCODING;
    }
    status = readLength(der + 1, available - 1, &length, &headerBytes);
    if (status != STARKECDSA_OK) {
        return status;
    }
    if (length > available - 1 - headerBytes) {
        return STARKECDSA_ERROR_ENCODING;
    }
    *body = der + 1 + headerBytes;
    *bodyLength = length;
    if (consumed != NULL) {
        *consumed = 1 + headerBytes + length;
    }
    return STARKECDSA_OK;
}

/* The outer element must account for every byte it was handed. */
static int readExact(const unsigned char *der, size_t available, unsigned char tag,
                     const unsigned char **body, size_t *bodyLength)
{
    size_t consumed = 0;
    int status = starkecdsaDerReadTag(der, available, tag, body, bodyLength, &consumed);
    if (status != STARKECDSA_OK) {
        return status;
    }
    if (consumed != available) {
        return STARKECDSA_ERROR_ENCODING;
    }
    return STARKECDSA_OK;
}

int starkecdsaDerReadSequence(const unsigned char *der, size_t available,
                              const unsigned char **body, size_t *bodyLength)
{
    return readExact(der, available, TAG_SEQUENCE, body, bodyLength);
}

/*
 * A BIT STRING holding a point carries a leading zero for the unused-bits
 * count, then the 0x04 uncompressed tag, then X and Y - and nothing else.
 */
static int readPointBitString(const unsigned char *der, size_t available, unsigned char *point)
{
    const unsigned char *body = NULL;
    size_t bodyLength = 0;
    int status = readExact(der, available, TAG_BIT_STRING, &body, &bodyLength);

    if (status != STARKECDSA_OK) {
        return status;
    }
    if (bodyLength != 2 + STARKECDSA_POINT_BYTES || body[0] != 0x00 || body[1] != 0x04) {
        return STARKECDSA_ERROR_ENCODING;
    }
    memcpy(point, body + 2, STARKECDSA_POINT_BYTES);
    return STARKECDSA_OK;
}

static int matchesCurveOid(const unsigned char *oidBody, size_t oidLength)
{
    return oidLength == sizeof(starkecdsaCurveOidDer) - 2
        && memcmp(oidBody, starkecdsaCurveOidDer + 2, oidLength) == 0;
}

int starkecdsaDerReadPrivateKey(const unsigned char *der, size_t available,
                                unsigned char *secret, unsigned char *pointOrNull, int *hasPoint)
{
    const unsigned char *body = NULL;
    const unsigned char *cursor;
    const unsigned char *field = NULL;
    const unsigned char *oidBody = NULL;
    size_t bodyLength = 0;
    size_t fieldLength = 0;
    size_t oidLength = 0;
    size_t consumed = 0;
    size_t remaining;
    int status;

    *hasPoint = 0;

    status = starkecdsaDerReadSequence(der, available, &body, &bodyLength);
    if (status != STARKECDSA_OK) {
        return status;
    }
    cursor = body;
    remaining = bodyLength;

    /* version, which SEC1 fixes at 1 */
    status = starkecdsaDerReadTag(cursor, remaining, TAG_INTEGER, &field, &fieldLength, &consumed);
    if (status != STARKECDSA_OK) {
        return status;
    }
    if (fieldLength != 1 || field[0] != 0x01) {
        return STARKECDSA_ERROR_ENCODING;
    }
    cursor += consumed;
    remaining -= consumed;

    status = starkecdsaDerReadTag(cursor, remaining, TAG_OCTET_STRING, &field, &fieldLength, &consumed);
    if (status != STARKECDSA_OK) {
        return status;
    }
    /* OpenSSL writes exactly 32 bytes; accept a shorter one left-padded. */
    if (fieldLength == 0 || fieldLength > STARKECDSA_SECRET_BYTES) {
        return STARKECDSA_ERROR_ENCODING;
    }
    memset(secret, 0, STARKECDSA_SECRET_BYTES);
    memcpy(secret + (STARKECDSA_SECRET_BYTES - fieldLength), field, fieldLength);
    cursor += consumed;
    remaining -= consumed;

    /* [0] curve OID - required here. A missing or mistagged container would
       otherwise skip the one check that catches a key from another curve. */
    status = starkecdsaDerReadTag(cursor, remaining, TAG_CONTEXT_0, &field, &fieldLength, &consumed);
    if (status != STARKECDSA_OK) {
        starkecdsaScrub(secret, STARKECDSA_SECRET_BYTES);
        return status;
    }
    if (readExact(field, fieldLength, TAG_OID, &oidBody, &oidLength) != STARKECDSA_OK) {
        starkecdsaScrub(secret, STARKECDSA_SECRET_BYTES);
        return STARKECDSA_ERROR_ENCODING;
    }
    if (!matchesCurveOid(oidBody, oidLength)) {
        starkecdsaScrub(secret, STARKECDSA_SECRET_BYTES);
        return STARKECDSA_ERROR_CURVE;
    }
    cursor += consumed;
    remaining -= consumed;

    /* [1] public key - required too, so the key-pair check can never be
       skipped by leaving it out. */
    status = starkecdsaDerReadTag(cursor, remaining, TAG_CONTEXT_1, &field, &fieldLength, &consumed);
    if (status != STARKECDSA_OK) {
        starkecdsaScrub(secret, STARKECDSA_SECRET_BYTES);
        return status;
    }
    if (pointOrNull != NULL) {
        status = readPointBitString(field, fieldLength, pointOrNull);
        if (status != STARKECDSA_OK) {
            starkecdsaScrub(secret, STARKECDSA_SECRET_BYTES);
            return status;
        }
        *hasPoint = 1;
    }
    cursor += consumed;
    remaining -= consumed;

    if (remaining != 0) {
        starkecdsaScrub(secret, STARKECDSA_SECRET_BYTES);
        return STARKECDSA_ERROR_ENCODING;
    }
    return STARKECDSA_OK;
}

int starkecdsaDerReadPublicKey(const unsigned char *der, size_t available, unsigned char *point)
{
    const unsigned char *body = NULL;
    const unsigned char *algorithm = NULL;
    const unsigned char *oidBody = NULL;
    size_t bodyLength = 0;
    size_t algorithmLength = 0;
    size_t oidLength = 0;
    size_t consumed = 0;
    size_t inner = 0;
    int status;

    status = starkecdsaDerReadSequence(der, available, &body, &bodyLength);
    if (status != STARKECDSA_OK) {
        return status;
    }
    status = starkecdsaDerReadTag(body, bodyLength, TAG_SEQUENCE, &algorithm, &algorithmLength, &consumed);
    if (status != STARKECDSA_OK) {
        return status;
    }

    /* algorithm identifier: id-ecPublicKey then the curve, and nothing else */
    status = starkecdsaDerReadTag(algorithm, algorithmLength, TAG_OID, &oidBody, &oidLength, &inner);
    if (status != STARKECDSA_OK) {
        return status;
    }
    if (oidLength != sizeof(starkecdsaPublicKeyOidDer) - 2
        || memcmp(oidBody, starkecdsaPublicKeyOidDer + 2, oidLength) != 0) {
        return STARKECDSA_ERROR_ENCODING;
    }
    status = readExact(algorithm + inner, algorithmLength - inner, TAG_OID, &oidBody, &oidLength);
    if (status != STARKECDSA_OK) {
        return status;
    }
    if (!matchesCurveOid(oidBody, oidLength)) {
        return STARKECDSA_ERROR_CURVE;
    }

    /* the BIT STRING must be the last thing in the outer SEQUENCE */
    return readPointBitString(body + consumed, bodyLength - consumed, point);
}

/* ------------------------------------------------------------------ writing */

static size_t lengthHeaderSize(size_t length)
{
    if (length < 128) {
        return 1;
    }
    if (length < 256) {
        return 2;
    }
    return 3;
}

static size_t writeLength(unsigned char *out, size_t length)
{
    if (length < 128) {
        out[0] = (unsigned char)length;
        return 1;
    }
    if (length < 256) {
        out[0] = 0x81;
        out[1] = (unsigned char)length;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (unsigned char)((length >> 8) & 0xffu);
    out[2] = (unsigned char)(length & 0xffu);
    return 3;
}

static size_t writeHeader(unsigned char *out, unsigned char tag, size_t length)
{
    out[0] = tag;
    return 1 + writeLength(out + 1, length);
}

static size_t wrappedSize(size_t contentLength)
{
    return 1 + lengthHeaderSize(contentLength) + contentLength;
}

int starkecdsaDerWritePrivateKey(const unsigned char *secret, const unsigned char *point,
                                 unsigned char **out, size_t *outLength)
{
    size_t versionSize = wrappedSize(1);
    size_t secretSize = wrappedSize(STARKECDSA_SECRET_BYTES);
    size_t oidSize = wrappedSize(sizeof(starkecdsaCurveOidDer));
    size_t pointBitStringSize = wrappedSize(2 + STARKECDSA_POINT_BYTES);
    size_t pointSize = wrappedSize(pointBitStringSize);
    size_t bodySize = versionSize + secretSize + oidSize + pointSize;
    size_t total = wrappedSize(bodySize);
    unsigned char *buffer = (unsigned char *)malloc(total);
    size_t offset = 0;

    if (buffer == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }

    offset += writeHeader(buffer + offset, TAG_SEQUENCE, bodySize);

    offset += writeHeader(buffer + offset, TAG_INTEGER, 1);
    buffer[offset++] = 0x01;

    offset += writeHeader(buffer + offset, TAG_OCTET_STRING, STARKECDSA_SECRET_BYTES);
    memcpy(buffer + offset, secret, STARKECDSA_SECRET_BYTES);
    offset += STARKECDSA_SECRET_BYTES;

    offset += writeHeader(buffer + offset, TAG_CONTEXT_0, sizeof(starkecdsaCurveOidDer));
    memcpy(buffer + offset, starkecdsaCurveOidDer, sizeof(starkecdsaCurveOidDer));
    offset += sizeof(starkecdsaCurveOidDer);

    offset += writeHeader(buffer + offset, TAG_CONTEXT_1, pointBitStringSize);
    offset += writeHeader(buffer + offset, TAG_BIT_STRING, 2 + STARKECDSA_POINT_BYTES);
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x04;
    memcpy(buffer + offset, point, STARKECDSA_POINT_BYTES);
    offset += STARKECDSA_POINT_BYTES;

    *out = buffer;
    *outLength = offset;
    return STARKECDSA_OK;
}

int starkecdsaDerWritePublicKey(const unsigned char *point, unsigned char **out, size_t *outLength)
{
    size_t algorithmBody = sizeof(starkecdsaPublicKeyOidDer) + sizeof(starkecdsaCurveOidDer);
    size_t algorithmSize = wrappedSize(algorithmBody);
    size_t bitStringSize = wrappedSize(2 + STARKECDSA_POINT_BYTES);
    size_t bodySize = algorithmSize + bitStringSize;
    size_t total = wrappedSize(bodySize);
    unsigned char *buffer = (unsigned char *)malloc(total);
    size_t offset = 0;

    if (buffer == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }

    offset += writeHeader(buffer + offset, TAG_SEQUENCE, bodySize);
    offset += writeHeader(buffer + offset, TAG_SEQUENCE, algorithmBody);
    memcpy(buffer + offset, starkecdsaPublicKeyOidDer, sizeof(starkecdsaPublicKeyOidDer));
    offset += sizeof(starkecdsaPublicKeyOidDer);
    memcpy(buffer + offset, starkecdsaCurveOidDer, sizeof(starkecdsaCurveOidDer));
    offset += sizeof(starkecdsaCurveOidDer);

    offset += writeHeader(buffer + offset, TAG_BIT_STRING, 2 + STARKECDSA_POINT_BYTES);
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x04;
    memcpy(buffer + offset, point, STARKECDSA_POINT_BYTES);
    offset += STARKECDSA_POINT_BYTES;

    *out = buffer;
    *outLength = offset;
    return STARKECDSA_OK;
}
