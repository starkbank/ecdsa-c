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
 *     belong to different C runtimes. Buffers that carry private key
 *     material (to_string, to_der, to_pem of a private key) are released with
 *     starkecdsa_free_secret so they are wiped first.
 *   - the calling convention is cdecl. STARKECDSA_CALL spells it out on
 *     Win32, where a Delphi or .NET host would otherwise default to another.
 *   - on any non-OK return, an out parameter is set to NULL and nothing needs
 *     freeing; a host may check the handle instead of the code.
 *   - no entry point terminates the process. Misuse and internal failures
 *     come back as a return code.
 *   - the library is safe to call from several threads at once: its only
 *     shared state is initialized exactly once and never changes afterwards.
 *     Secrets live in ordinary heap memory: they are wiped when released but
 *     not locked against paging or core dumps.
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

/* Explicit on Win32, where the default depends on the host's compiler settings. */
#if defined(_WIN32) && !defined(_WIN64)
#  define STARKECDSA_CALL __cdecl
#else
#  define STARKECDSA_CALL
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

/* The release this header belongs to; starkecdsa_version() returns the same text. */
#define STARKECDSA_VERSION "0.1.0"

typedef struct starkecdsa_private_key starkecdsa_private_key;
typedef struct starkecdsa_public_key starkecdsa_public_key;
typedef struct starkecdsa_signature starkecdsa_signature;

/* ---------------------------------------------------------------- library */

STARKECDSA_API int STARKECDSA_CALL starkecdsa_abi_version(void);
STARKECDSA_API const char *STARKECDSA_CALL starkecdsa_version(void);
STARKECDSA_API const char *STARKECDSA_CALL starkecdsa_strerror(int code);

/* Releases any buffer or string this library returned through an out param. */
STARKECDSA_API void STARKECDSA_CALL starkecdsa_free(void *pointer);

/* Wipes length bytes, then releases. Required for private key strings and
   encodings; harmless for anything else. */
STARKECDSA_API void STARKECDSA_CALL starkecdsa_free_secret(void *pointer, size_t length);

/* ------------------------------------------------------------ private key */

STARKECDSA_API int STARKECDSA_CALL starkecdsa_private_key_new(starkecdsa_private_key **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_private_key_from_pem(const char *pem, starkecdsa_private_key **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_private_key_from_der(const unsigned char *der, size_t der_len, starkecdsa_private_key **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_private_key_from_string(const char *hex, starkecdsa_private_key **out);

STARKECDSA_API int STARKECDSA_CALL starkecdsa_private_key_to_pem(const starkecdsa_private_key *key, char **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_private_key_to_der(const starkecdsa_private_key *key, unsigned char **out, size_t *out_len);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_private_key_to_string(const starkecdsa_private_key *key, char **out);

STARKECDSA_API int STARKECDSA_CALL starkecdsa_private_key_public_key(const starkecdsa_private_key *key, starkecdsa_public_key **out);

/* Zeroes the secret before releasing it. */
STARKECDSA_API void STARKECDSA_CALL starkecdsa_private_key_free(starkecdsa_private_key *key);

/* ------------------------------------------------------------- public key */

STARKECDSA_API int STARKECDSA_CALL starkecdsa_public_key_from_pem(const char *pem, starkecdsa_public_key **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_public_key_from_der(const unsigned char *der, size_t der_len, starkecdsa_public_key **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_public_key_from_string(const char *hex, starkecdsa_public_key **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_public_key_from_compressed(const char *hex, starkecdsa_public_key **out);

STARKECDSA_API int STARKECDSA_CALL starkecdsa_public_key_to_pem(const starkecdsa_public_key *key, char **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_public_key_to_der(const starkecdsa_public_key *key, unsigned char **out, size_t *out_len);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_public_key_to_string(const starkecdsa_public_key *key, char **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_public_key_to_compressed(const starkecdsa_public_key *key, char **out);

STARKECDSA_API void STARKECDSA_CALL starkecdsa_public_key_free(starkecdsa_public_key *key);

/* -------------------------------------------------------------- signature */

/*
 * The Digital-Signature request header carries the BARE DER sequence: pass 0.
 * The Stark API parses it without a recovery byte and rejects one that has it.
 * with_recovery_id = 1 prepends 27 + recoveryId, for callers that need the
 * recoverable form for their own purposes; it is never sent to Stark.
 */
STARKECDSA_API int STARKECDSA_CALL starkecdsa_signature_to_der(const starkecdsa_signature *signature, int with_recovery_id, unsigned char **out, size_t *out_len);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_signature_to_base64(const starkecdsa_signature *signature, int with_recovery_id, char **out);

STARKECDSA_API int STARKECDSA_CALL starkecdsa_signature_from_der(const unsigned char *der, size_t der_len, int with_recovery_id, starkecdsa_signature **out);
STARKECDSA_API int STARKECDSA_CALL starkecdsa_signature_from_base64(const char *base64, int with_recovery_id, starkecdsa_signature **out);

/* Returns the recovery id in [0, 3], or a negative code if none is known. */
STARKECDSA_API int STARKECDSA_CALL starkecdsa_signature_recovery_id(const starkecdsa_signature *signature);

STARKECDSA_API void STARKECDSA_CALL starkecdsa_signature_free(starkecdsa_signature *signature);

/* ------------------------------------------------------------------- sign */

/*
 * Hashes message with SHA-256 and signs it. The nonce follows hedged
 * RFC 6979: deterministic derivation with fresh entropy mixed in, so a
 * repeated message does not repeat the signature while a failing system RNG
 * still cannot leak the key. s is normalized to the lower half of the order.
 */
STARKECDSA_API int STARKECDSA_CALL starkecdsa_sign(const unsigned char *message, size_t message_len, const starkecdsa_private_key *key, starkecdsa_signature **out);

/*
 * Returns STARKECDSA_OK when the signature is valid, STARKECDSA_ERROR_RANGE
 * when it is well-formed but does not match, or another negative code when an
 * argument is unusable. Never returns OK on a malformed input.
 */
STARKECDSA_API int STARKECDSA_CALL starkecdsa_verify(const unsigned char *message, size_t message_len, const starkecdsa_signature *signature, const starkecdsa_public_key *key);

#ifdef __cplusplus
}
#endif

#endif /* STARKECDSA_H */
