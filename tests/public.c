/*
 * Built against include/starkecdsa.h and the shared library only. It cannot
 * see a single internal symbol, so if it compiles, links and passes, the
 * public surface is sufficient and the export list is what the README claims.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "starkecdsa.h"

static int passed;
static int failed;

static void check(const char *name, int ok)
{
    if (ok) {
        passed++;
        printf("  ok   %s\n", name);
        return;
    }
    failed++;
    printf("  FAIL %s\n", name);
}

static char *readFile(const char *name, size_t *length)
{
    char path[512];
    FILE *handle;
    char *buffer;
    long size;

    snprintf(path, sizeof(path), "%s/%s", TEST_FIXTURE_DIR, name);
    handle = fopen(path, "rb");
    if (handle == NULL) {
        return NULL;
    }
    fseek(handle, 0, SEEK_END);
    size = ftell(handle);
    fseek(handle, 0, SEEK_SET);
    buffer = (char *)malloc((size_t)size + 1);
    if (buffer == NULL || fread(buffer, 1, (size_t)size, handle) != (size_t)size) {
        free(buffer);
        fclose(handle);
        return NULL;
    }
    fclose(handle);
    buffer[size] = '\0';
    if (length != NULL) {
        *length = (size_t)size;
    }
    return buffer;
}

int main(void)
{
    size_t messageLength = 0;
    size_t signatureLength = 0;
    char *privatePem = readFile("privateKey.pem", NULL);
    char *publicPem = readFile("publicKey.pem", NULL);
    char *message = readFile("message.txt", &messageLength);
    char *signatureDer = readFile("signatureDer.txt", &signatureLength);
    starkecdsa_private_key *privateKey = NULL;
    starkecdsa_public_key *publicKey = NULL;
    starkecdsa_signature *signature = NULL;
    starkecdsa_signature *ours = NULL;
    char *header = NULL;

    printf("\nPublic API over the shared library\n");
    if (privatePem == NULL || publicPem == NULL || message == NULL || signatureDer == NULL) {
        printf("  FAIL fixtures readable\n");
        return 1;
    }
    check("abi version matches the header", starkecdsa_abi_version() == STARKECDSA_ABI_VERSION);
    check("version string matches the header", strcmp(starkecdsa_version(), STARKECDSA_VERSION) == 0);
    check("private key from pem", starkecdsa_private_key_from_pem(privatePem, &privateKey) == STARKECDSA_OK);
    check("public key from pem", starkecdsa_public_key_from_pem(publicPem, &publicKey) == STARKECDSA_OK);
    check("openssl signature parses",
          starkecdsa_signature_from_der((const unsigned char *)signatureDer, signatureLength, 0, &signature) == STARKECDSA_OK);
    check("openssl signature verifies",
          starkecdsa_verify((const unsigned char *)message, messageLength, signature, publicKey) == STARKECDSA_OK);
    check("sign", starkecdsa_sign((const unsigned char *)message, messageLength, privateKey, &ours) == STARKECDSA_OK);
    check("our signature verifies", starkecdsa_verify((const unsigned char *)message, messageLength, ours, publicKey) == STARKECDSA_OK);

    /* The Digital-Signature header is the bare DER, base64: no recovery byte. */
    check("header form is base64 of bare DER", starkecdsa_signature_to_base64(ours, 0, &header) == STARKECDSA_OK
          && header != NULL && strncmp(header, "ME", 2) == 0);
    starkecdsa_free(header);

    {
        /* on failure the out parameter is NULL, so a host may test the handle */
        starkecdsa_private_key *bad = privateKey;
        check("failed load nulls the out parameter",
              starkecdsa_private_key_from_pem("not a pem", &bad) != STARKECDSA_OK && bad == NULL);
    }

    starkecdsa_signature_free(ours);
    starkecdsa_signature_free(signature);
    starkecdsa_public_key_free(publicKey);
    starkecdsa_private_key_free(privateKey);
    free(privatePem);
    free(publicPem);
    free(message);
    free(signatureDer);

    printf("\n%d/%d passed\n", passed, passed + failed);
    return failed == 0 ? 0 : 1;
}
