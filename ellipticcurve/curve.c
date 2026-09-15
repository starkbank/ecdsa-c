/*
 * secp256k1 constants, and the one libsecp256k1 context the library shares.
 *
 * Only the order is kept as bytes: every other curve parameter lives inside
 * libsecp256k1, and duplicating them here would invite the two copies to
 * disagree. The order is needed because range checks on a secret happen before
 * libsecp256k1 ever sees it.
 */

#include <stdlib.h>
#include <string.h>
#include "internal.h"
#include "secp256k1.h"

/* n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 */
const unsigned char starkecdsaCurveOrder[STARKECDSA_SECRET_BYTES] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};

/* OBJECT IDENTIFIER 1.3.132.0.10, the secp256k1 curve */
const unsigned char starkecdsaCurveOidDer[7] = {
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a
};

/* OBJECT IDENTIFIER 1.2.840.10045.2.1, id-ecPublicKey */
const unsigned char starkecdsaPublicKeyOidDer[9] = {
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
};

static secp256k1_context *context;

/*
 * Created on first use and never destroyed: the context is immutable once
 * built, so sharing it across threads is safe, and the process keeps it until
 * exit. Racing first calls may build two, in which case one is discarded --
 * wasteful once, never wrong. A caller that needs strict single
 * initialisation should make one call before starting threads.
 */
const void *starkecdsaContext(void)
{
    if (context == NULL) {
        context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    }
    return context;
}

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  include <stdlib.h>
#else
#  include <stdio.h>
#  if defined(__linux__)
#    include <sys/random.h>
#  endif
#endif

/*
 * Entropy for the extra data mixed into the RFC 6979 nonce. A failure here
 * must stop the signature: falling back to something weaker would quietly
 * turn hedged signing into a nonce-reuse hazard.
 */
int starkecdsaRandomBytes(unsigned char *out, size_t length)
{
    if (out == NULL || length == 0) {
        return STARKECDSA_ERROR_ARGUMENT;
    }

#if defined(_WIN32)
    if (BCryptGenRandom(NULL, out, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return STARKECDSA_ERROR_ENTROPY;
    }
    return STARKECDSA_OK;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(out, length);
    return STARKECDSA_OK;
#else
#  if defined(__linux__) && defined(SYS_getrandom)
    {
        size_t filled = 0;
        while (filled < length) {
            ssize_t taken = getrandom(out + filled, length - filled, 0);
            if (taken < 0) {
                break;
            }
            filled += (size_t)taken;
        }
        if (filled == length) {
            return STARKECDSA_OK;
        }
    }
#  endif
    {
        FILE *source = fopen("/dev/urandom", "rb");
        size_t taken;
        if (source == NULL) {
            return STARKECDSA_ERROR_ENTROPY;
        }
        taken = fread(out, 1, length, source);
        fclose(source);
        if (taken != length) {
            return STARKECDSA_ERROR_ENTROPY;
        }
        return STARKECDSA_OK;
    }
#endif
}

int starkecdsa_abi_version(void)
{
    return STARKECDSA_ABI_VERSION;
}

const char *starkecdsa_version(void)
{
    return "0.1.0";
}

const char *starkecdsa_strerror(int code)
{
    switch (code) {
    case STARKECDSA_OK:
        return "ok";
    case STARKECDSA_ERROR_ARGUMENT:
        return "a required argument was null or out of range";
    case STARKECDSA_ERROR_MEMORY:
        return "out of memory";
    case STARKECDSA_ERROR_ENTROPY:
        return "the system random number generator was unavailable";
    case STARKECDSA_ERROR_ENCODING:
        return "the input was not valid DER, PEM, hex or base64";
    case STARKECDSA_ERROR_RANGE:
        return "the value was outside the range the curve allows";
    case STARKECDSA_ERROR_KEY_PAIR:
        return "the public key does not match the private key it was stored with";
    case STARKECDSA_ERROR_CURVE:
        return "the key was issued for a curve other than secp256k1";
    case STARKECDSA_ERROR_INTERNAL:
        return "the elliptic curve library rejected an operation";
    default:
        return "unknown error";
    }
}

void starkecdsa_free(void *pointer)
{
    free(pointer);
}
