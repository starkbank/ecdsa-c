/*
 * Internal surface. Nothing here is exported from the shared library: the
 * build hides every symbol by default and only the starkecdsa_* entry points
 * in include/starkecdsa.h are made visible, so two Stark libraries loaded into
 * one process cannot collide on these names.
 */

#ifndef STARKECDSA_INTERNAL_H
#define STARKECDSA_INTERNAL_H

#include <stddef.h>
#include "starkecdsa.h"

#define STARKECDSA_SECRET_BYTES 32
#define STARKECDSA_POINT_BYTES 64
#define STARKECDSA_SHA256_BYTES 32

struct starkecdsa_private_key {
    unsigned char secret[STARKECDSA_SECRET_BYTES];
};

struct starkecdsa_public_key {
    unsigned char point[STARKECDSA_POINT_BYTES];
};

struct starkecdsa_signature {
    unsigned char r[STARKECDSA_SECRET_BYTES];
    unsigned char s[STARKECDSA_SECRET_BYTES];
    int recoveryId;
};

/* curve.c -- secp256k1 constants and the shared libsecp256k1 context */

extern const unsigned char starkecdsaCurveOrder[STARKECDSA_SECRET_BYTES];
extern const unsigned char starkecdsaCurveOidDer[7];
extern const unsigned char starkecdsaPublicKeyOidDer[9];

/*
 * One context for the process, created on first use. libsecp256k1 contexts are
 * immutable after creation and safe to share between threads.
 */
const void *starkecdsaContext(void);

int starkecdsaRandomBytes(unsigned char *out, size_t length);

/* Returns -1, 0 or 1 comparing two fixed-width big-endian values. */
int starkecdsaCompareBytes(const unsigned char *left, const unsigned char *right, size_t length);
int starkecdsaIsZeroBytes(const unsigned char *value, size_t length);

/* utils/sha256.c */

void starkecdsaSha256(const unsigned char *message, size_t length, unsigned char *digest);

/* utils/binary.c */

void starkecdsaHexFromBytes(const unsigned char *bytes, size_t length, char *out);
int starkecdsaBytesFromHex(const char *hex, unsigned char *out, size_t expectedLength);
int starkecdsaAllocHexFromBytes(const unsigned char *bytes, size_t length, char **out);

/* utils/base64.c */

int starkecdsaBase64FromBytes(const unsigned char *bytes, size_t length, char **out);
int starkecdsaBytesFromBase64(const char *base64, unsigned char **out, size_t *outLength);

/* utils/der.c -- only the shapes this library emits and reads */

int starkecdsaDerReadSequence(const unsigned char *der, size_t length, const unsigned char **body, size_t *bodyLength);
int starkecdsaDerReadTag(const unsigned char *der, size_t length, unsigned char tag,
                         const unsigned char **body, size_t *bodyLength, size_t *consumed);

int starkecdsaDerWritePrivateKey(const unsigned char *secret, const unsigned char *point,
                                 unsigned char **out, size_t *outLength);
int starkecdsaDerReadPrivateKey(const unsigned char *der, size_t length,
                                unsigned char *secret, unsigned char *pointOrNull, int *hasPoint);

int starkecdsaDerWritePublicKey(const unsigned char *point, unsigned char **out, size_t *outLength);
int starkecdsaDerReadPublicKey(const unsigned char *der, size_t length, unsigned char *point);

/* utils/pem.c */

int starkecdsaPemWrite(const char *label, const unsigned char *der, size_t derLength, char **out);
int starkecdsaPemRead(const char *pem, const char *label, unsigned char **der, size_t *derLength);

#endif /* STARKECDSA_INTERNAL_H */
