/*
 * starkecdsa - ECDSA over secp256k1 for the Stark Bank and Stark Infra APIs.
 *
 * This header is the ABI. It is deliberately restricted to constructs a C89
 * compiler accepts, so it can also be included by old toolchains, translated
 * to a Delphi unit, or read by an FFI generator:
 *
 *   - no // comments, no inline, no variadic macros, no bool
 *   - no stdint types and no long anywhere in the ABI; long is 32 bits on
 *     Win64 and 64 bits on LP64, so the same header would describe two
 *     different layouts
 *   - every object is an opaque pointer, so struct layout, packing and
 *     alignment never cross the boundary
 *   - every buffer this library allocates is released with
 *     starkecdsa_free, never the caller's free: on Windows the two may
 *     belong to different C runtimes
 */

#ifndef STARKECDSA_H
#define STARKECDSA_H

#include <stddef.h>

#if defined(_WIN32)
#  if defined(STARKECDSA_BUILD_SHARED)
#    define STARKECDSA_API __declspec(dllexport)
#  elif defined(STARKECDSA_USE_SHARED)
#    define STARKECDSA_API __declspec(dllimport)
#  else
#    define STARKECDSA_API
#  endif
#else
#  if defined(STARKECDSA_BUILD_SHARED)
#    define STARKECDSA_API __attribute__((visibility("default")))
#  else
#    define STARKECDSA_API
#  endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes. Every function returns STARKECDSA_OK or a negative value. */
#define STARKECDSA_OK                 0
#define STARKECDSA_ERROR_ARGUMENT    (-1)
#define STARKECDSA_ERROR_MEMORY      (-2)
#define STARKECDSA_ERROR_ENTROPY     (-3)
#define STARKECDSA_ERROR_ENCODING    (-4)
#define STARKECDSA_ERROR_RANGE       (-5)
#define STARKECDSA_ERROR_KEY_PAIR    (-6)
#define STARKECDSA_ERROR_CURVE       (-7)
#define STARKECDSA_ERROR_INTERNAL    (-8)

/*
 * Bumped only when the layout or meaning of anything above changes. A caller
 * that links against a different major than it compiled with should refuse to
 * run rather than trust the symbols it resolved.
 */
#define STARKECDSA_ABI_VERSION 1

typedef struct starkecdsa_private_key starkecdsa_private_key;
typedef struct starkecdsa_public_key starkecdsa_public_key;
typedef struct starkecdsa_signature starkecdsa_signature;

/* ---------------------------------------------------------------- library */

STARKECDSA_API int starkecdsa_abi_version(void);
STARKECDSA_API const char *starkecdsa_version(void);
STARKECDSA_API const char *starkecdsa_strerror(int code);

/* Releases any buffer or string this library returned through an out param. */
STARKECDSA_API void starkecdsa_free(void *pointer);

/* ------------------------------------------------------------ private key */

STARKECDSA_API int starkecdsa_private_key_new(starkecdsa_private_key **out);
STARKECDSA_API int starkecdsa_private_key_from_pem(const char *pem, starkecdsa_private_key **out);
STARKECDSA_API int starkecdsa_private_key_from_der(const unsigned char *der, size_t der_len, starkecdsa_private_key **out);
STARKECDSA_API int starkecdsa_private_key_from_string(const char *hex, starkecdsa_private_key **out);

STARKECDSA_API int starkecdsa_private_key_to_pem(const starkecdsa_private_key *key, char **out);
STARKECDSA_API int starkecdsa_private_key_to_der(const starkecdsa_private_key *key, unsigned char **out, size_t *out_len);
STARKECDSA_API int starkecdsa_private_key_to_string(const starkecdsa_private_key *key, char **out);

STARKECDSA_API int starkecdsa_private_key_public_key(const starkecdsa_private_key *key, starkecdsa_public_key **out);

/* Zeroes the secret before releasing it. */
STARKECDSA_API void starkecdsa_private_key_free(starkecdsa_private_key *key);

/* ------------------------------------------------------------- public key */

STARKECDSA_API int starkecdsa_public_key_from_pem(const char *pem, starkecdsa_public_key **out);
STARKECDSA_API int starkecdsa_public_key_from_der(const unsigned char *der, size_t der_len, starkecdsa_public_key **out);
STARKECDSA_API int starkecdsa_public_key_from_string(const char *hex, starkecdsa_public_key **out);
STARKECDSA_API int starkecdsa_public_key_from_compressed(const char *hex, starkecdsa_public_key **out);

STARKECDSA_API int starkecdsa_public_key_to_pem(const starkecdsa_public_key *key, char **out);
STARKECDSA_API int starkecdsa_public_key_to_der(const starkecdsa_public_key *key, unsigned char **out, size_t *out_len);
STARKECDSA_API int starkecdsa_public_key_to_string(const starkecdsa_public_key *key, char **out);
STARKECDSA_API int starkecdsa_public_key_to_compressed(const starkecdsa_public_key *key, char **out);

STARKECDSA_API void starkecdsa_public_key_free(starkecdsa_public_key *key);

/* -------------------------------------------------------------- signature */

/*
 * with_recovery_id prepends the 27 + recoveryId byte that Stark's
 * Digital-Signature header carries. Pass 0 for the bare DER sequence.
 */
STARKECDSA_API int starkecdsa_signature_to_der(const starkecdsa_signature *signature, int with_recovery_id, unsigned char **out, size_t *out_len);
STARKECDSA_API int starkecdsa_signature_to_base64(const starkecdsa_signature *signature, int with_recovery_id, char **out);

STARKECDSA_API int starkecdsa_signature_from_der(const unsigned char *der, size_t der_len, int with_recovery_id, starkecdsa_signature **out);
STARKECDSA_API int starkecdsa_signature_from_base64(const char *base64, int with_recovery_id, starkecdsa_signature **out);

/* Returns the recovery id in [0, 3], or a negative code if none is known. */
STARKECDSA_API int starkecdsa_signature_recovery_id(const starkecdsa_signature *signature);

STARKECDSA_API void starkecdsa_signature_free(starkecdsa_signature *signature);

/* ------------------------------------------------------------------- sign */

/*
 * Hashes message with SHA-256 and signs it. The nonce follows hedged
 * RFC 6979: deterministic derivation with fresh entropy mixed in, so a
 * repeated message does not repeat the signature while a failing system RNG
 * still cannot leak the key. s is normalized to the lower half of the order.
 */
STARKECDSA_API int starkecdsa_sign(const unsigned char *message, size_t message_len, const starkecdsa_private_key *key, starkecdsa_signature **out);

/*
 * Returns STARKECDSA_OK when the signature is valid, STARKECDSA_ERROR_RANGE
 * when it is well-formed but does not match, or another negative code when an
 * argument is unusable. Never returns OK on a malformed input.
 */
STARKECDSA_API int starkecdsa_verify(const unsigned char *message, size_t message_len, const starkecdsa_signature *signature, const starkecdsa_public_key *key);

#ifdef __cplusplus
}
#endif

#endif /* STARKECDSA_H */
