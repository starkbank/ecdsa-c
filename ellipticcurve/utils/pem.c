/*
 * PEM with an explicit label. The label matters: a private key file written by
 * OpenSSL for secp256k1 begins with an EC PARAMETERS block, so a reader that
 * simply takes the first base64 run between dashes decodes the curve
 * parameters and then fails on them. tests/test.c covers exactly that file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../internal.h"

int starkecdsaPemWrite(const char *label, const unsigned char *der, size_t derLength, char **out)
{
    char *base64 = NULL;
    char *buffer;
    size_t base64Length;
    size_t lines;
    size_t total;
    size_t offset = 0;
    size_t index = 0;
    int status;

    if (label == NULL || der == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    status = starkecdsaBase64FromBytes(der, derLength, &base64);
    if (status != STARKECDSA_OK) {
        return status;
    }
    base64Length = strlen(base64);
    lines = (base64Length + 63) / 64;

    /* "-----BEGIN " + label + " -----\n" twice, plus wrapped body */
    total = (11 + strlen(label) + 6) * 2 + base64Length + lines + 8;
    buffer = (char *)malloc(total);
    if (buffer == NULL) {
        free(base64);
        return STARKECDSA_ERROR_MEMORY;
    }

    offset += (size_t)snprintf(buffer + offset, total - offset, "-----BEGIN %s-----\n", label);
    while (index < base64Length) {
        size_t chunk = base64Length - index;
        if (chunk > 64) {
            chunk = 64;
        }
        memcpy(buffer + offset, base64 + index, chunk);
        offset += chunk;
        buffer[offset++] = '\n';
        index += chunk;
    }
    offset += (size_t)snprintf(buffer + offset, total - offset, "-----END %s-----\n", label);
    buffer[offset] = '\0';

    free(base64);
    *out = buffer;
    return STARKECDSA_OK;
}

int starkecdsaPemRead(const char *pem, const char *label, unsigned char **der, size_t *derLength)
{
    char begin[96];
    char end[96];
    const char *start;
    const char *stop;
    char *body;
    size_t bodyLength;
    int status;

    if (pem == NULL || label == NULL || der == NULL || derLength == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    if (strlen(label) > 48) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    snprintf(begin, sizeof(begin), "-----BEGIN %s-----", label);
    snprintf(end, sizeof(end), "-----END %s-----", label);

    start = strstr(pem, begin);
    if (start == NULL) {
        return STARKECDSA_ERROR_ENCODING;
    }
    start += strlen(begin);
    stop = strstr(start, end);
    if (stop == NULL) {
        return STARKECDSA_ERROR_ENCODING;
    }

    bodyLength = (size_t)(stop - start);
    body = (char *)malloc(bodyLength + 1);
    if (body == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    memcpy(body, start, bodyLength);
    body[bodyLength] = '\0';

    status = starkecdsaBytesFromBase64(body, der, derLength);
    free(body);
    return status;
}
