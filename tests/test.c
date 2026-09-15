/*
 * The fixtures in this directory are byte-identical to the ones the Python,
 * Node, Go, Java, PHP, Ruby, Elixir, .NET and Clojure libraries test against,
 * and signatureDer.txt was produced by OpenSSL rather than by any of them:
 *
 *   openssl ecparam -name secp256k1 -genkey -out privateKey.pem
 *   openssl ec -in privateKey.pem -pubout -out publicKey.pem
 *   openssl dgst -sha256 -sign privateKey.pem -out signatureDer.txt message.txt
 *
 * So passing testVerifySignature means this library agrees with OpenSSL and
 * with the other ten, not merely with itself.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "starkecdsa.h"
#include "../ellipticcurve/internal.h"

static int passed;
static int failed;

static void startGroup(const char *name)
{
    printf("\n%s\n", name);
}

static void check(const char *name, int ok, const char *detail)
{
    if (ok) {
        passed++;
        printf("  ok   %s\n", name);
        return;
    }
    failed++;
    printf("  FAIL %s\n", name);
    if (detail != NULL && detail[0] != '\0') {
        printf("       %s\n", detail);
    }
}

static unsigned char *readFile(const char *name, size_t *length)
{
    char path[512];
    FILE *handle;
    unsigned char *buffer;
    long size;

    snprintf(path, sizeof(path), "%s/%s", TEST_FIXTURE_DIR, name);
    handle = fopen(path, "rb");
    if (handle == NULL) {
        return NULL;
    }
    fseek(handle, 0, SEEK_END);
    size = ftell(handle);
    fseek(handle, 0, SEEK_SET);
    buffer = (unsigned char *)malloc((size_t)size + 1);
    if (buffer == NULL) {
        fclose(handle);
        return NULL;
    }
    if (fread(buffer, 1, (size_t)size, handle) != (size_t)size) {
        free(buffer);
        fclose(handle);
        return NULL;
    }
    fclose(handle);
    buffer[size] = '\0';
    *length = (size_t)size;
    return buffer;
}

/* ------------------------------------------------------- vendored pieces */

static void testSha256(void)
{
    /* FIPS 180-4 / NIST CAVP vectors. */
    static const char *empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    static const char *abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    unsigned char digest[32];
    char hex[65];
    unsigned char *block;
    int ok;

    startGroup("SHA-256");

    starkecdsaSha256((const unsigned char *)"", 0, digest);
    starkecdsaHexFromBytes(digest, 32, hex);
    check("empty string", strcmp(hex, empty) == 0, hex);

    starkecdsaSha256((const unsigned char *)"abc", 3, digest);
    starkecdsaHexFromBytes(digest, 32, hex);
    check("\"abc\"", strcmp(hex, abc) == 0, hex);

    /* One million 'a' exercises multi-block and the length encoding. */
    block = (unsigned char *)malloc(1000000);
    memset(block, 'a', 1000000);
    starkecdsaSha256(block, 1000000, digest);
    starkecdsaHexFromBytes(digest, 32, hex);
    ok = strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0;
    check("one million 'a'", ok, hex);
    free(block);
}

static void testBase64(void)
{
    /* RFC 4648 section 10. */
    static const char *inputs[] = {"", "f", "fo", "foo", "foob", "fooba", "foobar"};
    static const char *outputs[] = {"", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"};
    size_t index;

    startGroup("Base64");

    for (index = 0; index < 7; index++) {
        char *encoded = NULL;
        unsigned char *decoded = NULL;
        size_t decodedLength = 0;
        size_t inputLength = strlen(inputs[index]);
        int ok;

        if (starkecdsaBase64FromBytes((const unsigned char *)inputs[index], inputLength, &encoded) != STARKECDSA_OK) {
            check(outputs[index], 0, "encode failed");
            continue;
        }
        ok = strcmp(encoded, outputs[index]) == 0;
        check(outputs[index][0] ? outputs[index] : "(empty)", ok, encoded);

        if (starkecdsaBytesFromBase64(encoded, &decoded, &decodedLength) == STARKECDSA_OK) {
            ok = decodedLength == inputLength && memcmp(decoded, inputs[index], inputLength) == 0;
            check("round trip", ok, NULL);
            free(decoded);
        } else {
            check("round trip", 0, "decode failed");
        }
        free(encoded);
    }
}

/* ------------------------------------------------------- the OpenSSL vector */

static void testOpenssl(void)
{
    unsigned char *privatePem;
    unsigned char *publicPem;
    unsigned char *message;
    unsigned char *signatureDer;
    size_t privateLength;
    size_t publicLength;
    size_t messageLength;
    size_t signatureLength;
    starkecdsa_private_key *privateKey = NULL;
    starkecdsa_public_key *publicKey = NULL;
    starkecdsa_public_key *derivedKey = NULL;
    starkecdsa_signature *signature = NULL;
    unsigned char *reencoded = NULL;
    size_t reencodedLength = 0;

    startGroup("OpenSSL interop");

    privatePem = readFile("privateKey.pem", &privateLength);
    publicPem = readFile("publicKey.pem", &publicLength);
    message = readFile("message.txt", &messageLength);
    signatureDer = readFile("signatureDer.txt", &signatureLength);

    if (privatePem == NULL || publicPem == NULL || message == NULL || signatureDer == NULL) {
        check("fixtures readable", 0, "could not read one of the fixture files");
        return;
    }
    check("fixtures readable", 1, NULL);

    /* The private key file carries an EC PARAMETERS block before the key. */
    check("private key parses past the EC PARAMETERS block",
          starkecdsa_private_key_from_pem((const char *)privatePem, &privateKey) == STARKECDSA_OK, NULL);

    check("public key parses",
          starkecdsa_public_key_from_pem((const char *)publicPem, &publicKey) == STARKECDSA_OK, NULL);

    if (privateKey != NULL) {
        check("public key derives from the private key",
              starkecdsa_private_key_public_key(privateKey, &derivedKey) == STARKECDSA_OK, NULL);
    }

    /* The pair has to agree, or the fixtures are not what we think. */
    if (publicKey != NULL && derivedKey != NULL) {
        char *fromFile = NULL;
        char *fromPair = NULL;
        starkecdsa_public_key_to_string(publicKey, &fromFile);
        starkecdsa_public_key_to_string(derivedKey, &fromPair);
        check("derived public key matches publicKey.pem",
              fromFile != NULL && fromPair != NULL && strcmp(fromFile, fromPair) == 0, fromPair);
        starkecdsa_free(fromFile);
        starkecdsa_free(fromPair);
    }

    /* This is the cross-library assertion: OpenSSL signed it, we verify it. */
    check("signature parses from OpenSSL DER",
          starkecdsa_signature_from_der(signatureDer, signatureLength, 0, &signature) == STARKECDSA_OK, NULL);

    if (signature != NULL) {
        check("re-encoding reproduces the OpenSSL bytes exactly",
              starkecdsa_signature_to_der(signature, 0, &reencoded, &reencodedLength) == STARKECDSA_OK
              && reencodedLength == signatureLength
              && memcmp(reencoded, signatureDer, signatureLength) == 0, NULL);
        starkecdsa_free(reencoded);
    }

    if (signature != NULL && publicKey != NULL) {
        check("OpenSSL signature verifies against publicKey.pem",
              starkecdsa_verify(message, messageLength, signature, publicKey) == STARKECDSA_OK, NULL);
    }

    /* And our own signature over the same message verifies too. */
    if (privateKey != NULL && derivedKey != NULL) {
        starkecdsa_signature *ours = NULL;
        check("we can sign the fixture message",
              starkecdsa_sign(message, messageLength, privateKey, &ours) == STARKECDSA_OK, NULL);
        check("our signature verifies",
              starkecdsa_verify(message, messageLength, ours, derivedKey) == STARKECDSA_OK, NULL);
        starkecdsa_signature_free(ours);
    }

    starkecdsa_signature_free(signature);
    starkecdsa_public_key_free(publicKey);
    starkecdsa_public_key_free(derivedKey);
    starkecdsa_private_key_free(privateKey);
    free(privatePem);
    free(publicPem);
    free(message);
    free(signatureDer);
}

/* --------------------------------------------------------------- sign/verify */

static void testSignVerify(void)
{
    starkecdsa_private_key *privateKey = NULL;
    starkecdsa_public_key *publicKey = NULL;
    starkecdsa_signature *signature = NULL;
    static const char *right = "This is the right message";
    static const char *wrong = "This is the wrong message";

    startGroup("Sign and verify");

    check("key generation", starkecdsa_private_key_new(&privateKey) == STARKECDSA_OK, NULL);
    if (privateKey == NULL) {
        return;
    }
    check("public key derivation", starkecdsa_private_key_public_key(privateKey, &publicKey) == STARKECDSA_OK, NULL);

    check("sign", starkecdsa_sign((const unsigned char *)right, strlen(right), privateKey, &signature) == STARKECDSA_OK, NULL);
    check("the right message verifies",
          starkecdsa_verify((const unsigned char *)right, strlen(right), signature, publicKey) == STARKECDSA_OK, NULL);
    check("the wrong message does not verify",
          starkecdsa_verify((const unsigned char *)wrong, strlen(wrong), signature, publicKey) != STARKECDSA_OK, NULL);

    check("recovery id is in [0, 3]",
          starkecdsa_signature_recovery_id(signature) >= 0 && starkecdsa_signature_recovery_id(signature) <= 3, NULL);

    /* Hedged RFC 6979: deterministic derivation, fresh entropy mixed in, so a
       repeated message must not repeat the signature. */
    {
        starkecdsa_signature *again = NULL;
        char *first = NULL;
        char *second = NULL;
        starkecdsa_sign((const unsigned char *)right, strlen(right), privateKey, &again);
        starkecdsa_signature_to_base64(signature, 0, &first);
        starkecdsa_signature_to_base64(again, 0, &second);
        check("signing twice does not repeat the signature",
              first != NULL && second != NULL && strcmp(first, second) != 0, first);
        check("the second signature also verifies",
              starkecdsa_verify((const unsigned char *)right, strlen(right), again, publicKey) == STARKECDSA_OK, NULL);
        starkecdsa_free(first);
        starkecdsa_free(second);
        starkecdsa_signature_free(again);
    }

    starkecdsa_signature_free(signature);
    starkecdsa_public_key_free(publicKey);
    starkecdsa_private_key_free(privateKey);
}

static void testMalformed(void)
{
    starkecdsa_private_key *privateKey = NULL;
    starkecdsa_private_key *rejected = NULL;
    starkecdsa_public_key *publicKey = NULL;
    starkecdsa_signature *signature = NULL;
    static const unsigned char zeroDer[] = {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00};
    static const char *message = "This is the wrong message";

    startGroup("Malformed input");

    starkecdsa_private_key_new(&privateKey);
    starkecdsa_private_key_public_key(privateKey, &publicKey);

    check("a zero signature is rejected, not accepted",
          starkecdsa_signature_from_der(zeroDer, sizeof(zeroDer), 0, &signature) != STARKECDSA_OK
          || starkecdsa_verify((const unsigned char *)message, strlen(message), signature, publicKey) != STARKECDSA_OK, NULL);
    starkecdsa_signature_free(signature);
    signature = NULL;

    check("truncated DER is rejected",
          starkecdsa_signature_from_der((const unsigned char *)"\x30\x44", 2, 0, &signature) != STARKECDSA_OK, NULL);

    check("a PEM with no key block is rejected",
          starkecdsa_private_key_from_pem("not a pem at all", &rejected) != STARKECDSA_OK, NULL);

    check("a secret of zero is rejected",
          starkecdsa_private_key_from_string("0000000000000000000000000000000000000000000000000000000000000000", &rejected)
          != STARKECDSA_OK, NULL);

    /* N itself is out of range: valid secrets are [1, N-1]. */
    check("a secret equal to the curve order is rejected",
          starkecdsa_private_key_from_string("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", &rejected)
          != STARKECDSA_OK, NULL);

    check("null arguments are rejected rather than dereferenced",
          starkecdsa_sign(NULL, 0, NULL, NULL) == STARKECDSA_ERROR_ARGUMENT, NULL);

    starkecdsa_public_key_free(publicKey);
    starkecdsa_private_key_free(privateKey);
}

/* ------------------------------------------------------------- round trips */

static void testRoundTrips(void)
{
    starkecdsa_private_key *privateKey = NULL;
    starkecdsa_private_key *reloaded = NULL;
    starkecdsa_public_key *publicKey = NULL;
    starkecdsa_public_key *reloadedPublic = NULL;
    char *pem = NULL;
    char *hex = NULL;
    char *other = NULL;
    char *compressed = NULL;
    unsigned char *der = NULL;
    size_t derLength = 0;

    startGroup("Encoding round trips");

    starkecdsa_private_key_new(&privateKey);
    starkecdsa_private_key_public_key(privateKey, &publicKey);

    check("private key PEM round trip",
          starkecdsa_private_key_to_pem(privateKey, &pem) == STARKECDSA_OK
          && starkecdsa_private_key_from_pem(pem, &reloaded) == STARKECDSA_OK
          && starkecdsa_private_key_to_string(privateKey, &hex) == STARKECDSA_OK
          && starkecdsa_private_key_to_string(reloaded, &other) == STARKECDSA_OK
          && strcmp(hex, other) == 0, NULL);
    starkecdsa_free(pem); pem = NULL;
    starkecdsa_free(hex); hex = NULL;
    starkecdsa_free(other); other = NULL;
    starkecdsa_private_key_free(reloaded); reloaded = NULL;

    check("private key DER round trip",
          starkecdsa_private_key_to_der(privateKey, &der, &derLength) == STARKECDSA_OK
          && starkecdsa_private_key_from_der(der, derLength, &reloaded) == STARKECDSA_OK, NULL);
    starkecdsa_free(der); der = NULL;
    starkecdsa_private_key_free(reloaded); reloaded = NULL;

    check("public key PEM round trip",
          starkecdsa_public_key_to_pem(publicKey, &pem) == STARKECDSA_OK
          && starkecdsa_public_key_from_pem(pem, &reloadedPublic) == STARKECDSA_OK
          && starkecdsa_public_key_to_string(publicKey, &hex) == STARKECDSA_OK
          && starkecdsa_public_key_to_string(reloadedPublic, &other) == STARKECDSA_OK
          && strcmp(hex, other) == 0, NULL);
    starkecdsa_free(pem); pem = NULL;
    starkecdsa_free(other); other = NULL;
    starkecdsa_public_key_free(reloadedPublic); reloadedPublic = NULL;

    check("compressed public key round trip",
          starkecdsa_public_key_to_compressed(publicKey, &compressed) == STARKECDSA_OK
          && starkecdsa_public_key_from_compressed(compressed, &reloadedPublic) == STARKECDSA_OK
          && starkecdsa_public_key_to_string(reloadedPublic, &other) == STARKECDSA_OK
          && strcmp(hex, other) == 0, compressed);
    check("compressed form is 33 bytes of hex with an 02 or 03 tag",
          compressed != NULL && strlen(compressed) == 66
          && (strncmp(compressed, "02", 2) == 0 || strncmp(compressed, "03", 2) == 0), compressed);
    starkecdsa_free(compressed);
    starkecdsa_free(hex);
    starkecdsa_free(other);
    starkecdsa_public_key_free(reloadedPublic);

    /* Signature base64, with and without the 27 + recoveryId prefix. */
    {
        starkecdsa_signature *signature = NULL;
        starkecdsa_signature *parsed = NULL;
        char *bare = NULL;
        char *withRecovery = NULL;
        static const char *message = "round trip";

        starkecdsa_sign((const unsigned char *)message, strlen(message), privateKey, &signature);

        check("signature base64 round trip",
              starkecdsa_signature_to_base64(signature, 0, &bare) == STARKECDSA_OK
              && starkecdsa_signature_from_base64(bare, 0, &parsed) == STARKECDSA_OK
              && starkecdsa_verify((const unsigned char *)message, strlen(message), parsed, publicKey) == STARKECDSA_OK, bare);
        starkecdsa_signature_free(parsed); parsed = NULL;

        check("signature base64 round trip carrying the recovery byte",
              starkecdsa_signature_to_base64(signature, 1, &withRecovery) == STARKECDSA_OK
              && starkecdsa_signature_from_base64(withRecovery, 1, &parsed) == STARKECDSA_OK
              && starkecdsa_signature_recovery_id(parsed) == starkecdsa_signature_recovery_id(signature)
              && starkecdsa_verify((const unsigned char *)message, strlen(message), parsed, publicKey) == STARKECDSA_OK,
              withRecovery);

        /* Base64 pads to a multiple of four, so one extra byte often encodes
           to the same number of characters. Assert the byte instead. */
        {
            unsigned char *bareDer = NULL;
            unsigned char *recoveryDer = NULL;
            size_t bareLength = 0;
            size_t recoveryLength = 0;
            int ok = 0;

            if (starkecdsa_signature_to_der(signature, 0, &bareDer, &bareLength) == STARKECDSA_OK
                && starkecdsa_signature_to_der(signature, 1, &recoveryDer, &recoveryLength) == STARKECDSA_OK) {
                ok = recoveryLength == bareLength + 1
                     && recoveryDer[0] == (unsigned char)(27 + starkecdsa_signature_recovery_id(signature))
                     && memcmp(recoveryDer + 1, bareDer, bareLength) == 0;
            }
            check("the recovery form is the bare DER behind a 27 + recoveryId byte", ok, NULL);
            starkecdsa_free(bareDer);
            starkecdsa_free(recoveryDer);
        }

        starkecdsa_free(bare);
        starkecdsa_free(withRecovery);
        starkecdsa_signature_free(parsed);
        starkecdsa_signature_free(signature);
    }

    starkecdsa_public_key_free(publicKey);
    starkecdsa_private_key_free(privateKey);
}

/* ------------------------------------------------ review negative cases */

#if !defined(_WIN32)
#include <pthread.h>

typedef struct {
    const starkecdsa_private_key *privateKey;
    const starkecdsa_public_key *publicKey;
    int failures;
} ThreadWork;

static void *signInThread(void *argument)
{
    ThreadWork *work = (ThreadWork *)argument;
    static const unsigned char message[] = "shared context, many threads";
    int round;
    for (round = 0; round < 50; round++) {
        starkecdsa_signature *signature = NULL;
        if (starkecdsa_sign(message, sizeof(message) - 1, work->privateKey, &signature) != STARKECDSA_OK
            || starkecdsa_verify(message, sizeof(message) - 1, signature, work->publicKey) != STARKECDSA_OK) {
            work->failures++;
        }
        starkecdsa_signature_free(signature);
    }
    return NULL;
}
#endif

static void testHardening(void)
{
    starkecdsa_private_key *privateKey = NULL;
    starkecdsa_private_key *probe = NULL;
    starkecdsa_public_key *publicKey = NULL;
    starkecdsa_public_key *publicProbe = NULL;
    starkecdsa_signature *signature = NULL;
    unsigned char *wrongCurve = NULL;
    unsigned char *foreignPoint = NULL;
    unsigned char *der = NULL;
    unsigned char *decoded = NULL;
    unsigned char bytes[STARKECDSA_SECRET_BYTES];
    unsigned char reference[STARKECDSA_SECRET_BYTES];
    size_t wrongCurveLength = 0;
    size_t foreignPointLength = 0;
    size_t derLength = 0;
    size_t decodedLength = 0;
    char *hex = NULL;
    /* r = n, the curve order, which no valid signature can carry; s = 1 */
    static const unsigned char rEqualsOrder[] = {
        0x30, 0x26, 0x02, 0x21, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        0x02, 0x01, 0x01
    };

    startGroup("Hardening");

    starkecdsa_private_key_new(&privateKey);
    starkecdsa_private_key_public_key(privateKey, &publicKey);
    wrongCurve = readFile("wrongCurve.pem", &wrongCurveLength);
    foreignPoint = readFile("foreignPoint.der", &foreignPointLength);
    check("fixtures for the negative cases are readable", wrongCurve != NULL && foreignPoint != NULL, NULL);

    /* key files: wrong curve, foreign point, structure */
    probe = privateKey;
    check("a prime256v1 private key is rejected as the wrong curve, and the out parameter is nulled",
          starkecdsa_private_key_from_pem((const char *)wrongCurve, &probe) == STARKECDSA_ERROR_CURVE && probe == NULL, NULL);
    probe = privateKey;
    check("a key file whose public point belongs to another secret is rejected",
          starkecdsa_private_key_from_der(foreignPoint, foreignPointLength, &probe) == STARKECDSA_ERROR_KEY_PAIR && probe == NULL, NULL);

    starkecdsa_private_key_to_der(privateKey, &der, &derLength);
    check("the key DER has the layout the structure tests assume",
          derLength == 118 && der[39] == 0xa0 && der[48] == 0xa1, NULL);
    {
        unsigned char edited[128];
        memcpy(edited, der, derLength);
        edited[derLength] = 0x00;
        check("a byte after the key SEQUENCE is rejected",
              starkecdsa_private_key_from_der(edited, derLength + 1, &probe) == STARKECDSA_ERROR_ENCODING, NULL);
        edited[1] = (unsigned char)(edited[1] + 1);
        check("a byte inside the key SEQUENCE after [1] is rejected",
              starkecdsa_private_key_from_der(edited, derLength + 1, &probe) == STARKECDSA_ERROR_ENCODING, NULL);

        /* drop the [0] curve container: 9 bytes at offset 39 */
        memcpy(edited, der, 39);
        memcpy(edited + 39, der + 48, derLength - 48);
        edited[1] = (unsigned char)(der[1] - 9);
        check("a key file without its [0] curve OID is rejected rather than trusted",
              starkecdsa_private_key_from_der(edited, derLength - 9, &probe) == STARKECDSA_ERROR_ENCODING, NULL);

        /* drop the [1] public key container: 70 bytes at offset 48 */
        memcpy(edited, der, 48);
        edited[1] = (unsigned char)(der[1] - 70);
        check("a key file without its [1] public point is rejected rather than trusted",
              starkecdsa_private_key_from_der(edited, 48, &probe) == STARKECDSA_ERROR_ENCODING, NULL);

        /* a foreign OID inside [0]: 1.3.132.0.7 instead of .10 */
        memcpy(edited, der, derLength);
        edited[47] = 0x07;
        check("a key file naming another curve inside [0] is rejected",
              starkecdsa_private_key_from_der(edited, derLength, &probe) == STARKECDSA_ERROR_CURVE, NULL);

        /* a long-form length where the short form fits */
        memcpy(edited + 1, der, derLength);
        edited[0] = 0x30;
        edited[1] = 0x81;
        check("a non-minimal DER length is rejected",
              starkecdsa_private_key_from_der(edited, derLength + 1, &probe) == STARKECDSA_ERROR_ENCODING, NULL);
    }
    starkecdsa_free_secret(der, derLength);

    /* signature DER: an out-of-range integer is refused at parse time, not zeroed */
    check("a signature with r equal to the curve order is refused at parse time",
          starkecdsa_signature_from_der(rEqualsOrder, sizeof(rEqualsOrder), 0, &signature) != STARKECDSA_OK && signature == NULL, NULL);

    /* base64 quantum */
    check("base64 with 4k+1 data characters is rejected",
          starkecdsaBytesFromBase64("QUJDR", &decoded, &decodedLength) == STARKECDSA_ERROR_ENCODING, NULL);
    check("base64 missing its padding is rejected",
          starkecdsaBytesFromBase64("QQ", &decoded, &decodedLength) == STARKECDSA_ERROR_ENCODING, NULL);
    check("base64 with non-zero leftover bits is rejected",
          starkecdsaBytesFromBase64("QR==", &decoded, &decodedLength) == STARKECDSA_ERROR_ENCODING, NULL);
    check("base64 data after padding is rejected",
          starkecdsaBytesFromBase64("QQ==QQ==", &decoded, &decodedLength) == STARKECDSA_ERROR_ENCODING, NULL);
    check("canonical padded base64 decodes",
          starkecdsaBytesFromBase64("QQ==", &decoded, &decodedLength) == STARKECDSA_OK && decodedLength == 1 && decoded[0] == 'A', NULL);
    free(decoded);
    decoded = NULL;
    check("whitespace inside a base64 body is skipped",
          starkecdsaBytesFromBase64("QU\nJD\r\n", &decoded, &decodedLength) == STARKECDSA_OK && decodedLength == 3 && memcmp(decoded, "ABC", 3) == 0, NULL);
    free(decoded);

    /* hex: python's int(x, 16) semantics */
    memset(reference, 0, sizeof(reference));
    reference[31] = 0x01;
    check("a hex secret written without leading zeros denotes the same value",
          starkecdsaBytesFromHex("1", bytes, sizeof(bytes)) == STARKECDSA_OK && memcmp(bytes, reference, sizeof(bytes)) == 0
          && starkecdsaBytesFromHex("0001", bytes, sizeof(bytes)) == STARKECDSA_OK && memcmp(bytes, reference, sizeof(bytes)) == 0, NULL);
    reference[30] = 0x0a;
    reference[31] = 0xbc;
    check("an odd number of hex digits reads as a leading half byte",
          starkecdsaBytesFromHex("abc", bytes, sizeof(bytes)) == STARKECDSA_OK && memcmp(bytes, reference, sizeof(bytes)) == 0, NULL);
    check("hex wider than the field is rejected",
          starkecdsaBytesFromHex("10000000000000000000000000000000000000000000000000000000000000000", bytes, sizeof(bytes)) == STARKECDSA_ERROR_ENCODING, NULL);

    /* misuse returns a code; nothing aborts */
    publicProbe = publicKey;
    check("an off-curve public point is refused with a code, and the out parameter is nulled",
          starkecdsa_public_key_from_string(
              "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
              &publicProbe) == STARKECDSA_ERROR_CURVE && publicProbe == NULL, NULL);
    check("freeing a null secret is safe", (starkecdsa_free_secret(NULL, 32), 1), NULL);
    check("a private key string is released through free_secret",
          starkecdsa_private_key_to_string(privateKey, &hex) == STARKECDSA_OK && (starkecdsa_free_secret(hex, strlen(hex)), 1), NULL);

#if !defined(_WIN32)
    {
        ThreadWork work[4];
        pthread_t threads[4];
        int index;
        int failures = 0;
        for (index = 0; index < 4; index++) {
            work[index].privateKey = privateKey;
            work[index].publicKey = publicKey;
            work[index].failures = 0;
            pthread_create(&threads[index], NULL, signInThread, &work[index]);
        }
        for (index = 0; index < 4; index++) {
            pthread_join(threads[index], NULL);
            failures += work[index].failures;
        }
        check("four threads sign and verify concurrently over the shared context", failures == 0, NULL);
    }
#endif

    free(wrongCurve);
    free(foreignPoint);
    starkecdsa_public_key_free(publicKey);
    starkecdsa_private_key_free(privateKey);
}

static void testLibrary(void)
{
    startGroup("Library");
    check("abi version is reported", starkecdsa_abi_version() == STARKECDSA_ABI_VERSION, NULL);
    check("version string is present", starkecdsa_version() != NULL && starkecdsa_version()[0] != '\0', starkecdsa_version());
    check("every error code has a message",
          strcmp(starkecdsa_strerror(STARKECDSA_ERROR_RANGE), starkecdsa_strerror(STARKECDSA_ERROR_MEMORY)) != 0, NULL);
    check("freeing null is safe", (starkecdsa_free(NULL), 1), NULL);
}

int main(void)
{
    testLibrary();
    testSha256();
    testBase64();
    testOpenssl();
    testSignVerify();
    testMalformed();
    testRoundTrips();
    testHardening();

    printf("\n%s\n", "------------------------------------------------------------");
    if (failed == 0) {
        printf("%d/%d passed\n", passed, passed);
        return 0;
    }
    printf("%d failed out of %d\n", failed, passed + failed);
    return 1;
}
