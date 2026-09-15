/* Base64 as RFC 4648 section 4, with padding. Tested against section 10. */

#include <stdlib.h>
#include <string.h>
#include "../internal.h"

static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int starkecdsaBase64FromBytes(const unsigned char *bytes, size_t length, char **out)
{
    size_t groups = (length + 2) / 3;
    size_t encodedLength = groups * 4;
    char *buffer;
    size_t source = 0;
    size_t target = 0;

    if (out == NULL || (bytes == NULL && length > 0)) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    buffer = (char *)malloc(encodedLength + 1);
    if (buffer == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }

    while (source + 3 <= length) {
        unsigned int triple = ((unsigned int)bytes[source] << 16)
                            | ((unsigned int)bytes[source + 1] << 8)
                            | (unsigned int)bytes[source + 2];
        buffer[target++] = alphabet[(triple >> 18) & 0x3fu];
        buffer[target++] = alphabet[(triple >> 12) & 0x3fu];
        buffer[target++] = alphabet[(triple >> 6) & 0x3fu];
        buffer[target++] = alphabet[triple & 0x3fu];
        source += 3;
    }

    if (length - source == 1) {
        unsigned int triple = (unsigned int)bytes[source] << 16;
        buffer[target++] = alphabet[(triple >> 18) & 0x3fu];
        buffer[target++] = alphabet[(triple >> 12) & 0x3fu];
        buffer[target++] = '=';
        buffer[target++] = '=';
    } else if (length - source == 2) {
        unsigned int triple = ((unsigned int)bytes[source] << 16) | ((unsigned int)bytes[source + 1] << 8);
        buffer[target++] = alphabet[(triple >> 18) & 0x3fu];
        buffer[target++] = alphabet[(triple >> 12) & 0x3fu];
        buffer[target++] = alphabet[(triple >> 6) & 0x3fu];
        buffer[target++] = '=';
    }

    buffer[target] = '\0';
    *out = buffer;
    return STARKECDSA_OK;
}

static int valueFromBase64Digit(char digit)
{
    if (digit >= 'A' && digit <= 'Z') {
        return digit - 'A';
    }
    if (digit >= 'a' && digit <= 'z') {
        return digit - 'a' + 26;
    }
    if (digit >= '0' && digit <= '9') {
        return digit - '0' + 52;
    }
    if (digit == '+') {
        return 62;
    }
    if (digit == '/') {
        return 63;
    }
    return -1;
}

/* Whitespace is skipped, so a PEM body can be handed over with its newlines. */
int starkecdsaBytesFromBase64(const char *base64, unsigned char **out, size_t *outLength)
{
    size_t length;
    unsigned char *buffer;
    unsigned int accumulator = 0;
    int bits = 0;
    size_t target = 0;
    size_t index;
    int padding = 0;

    if (base64 == NULL || out == NULL || outLength == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    length = strlen(base64);
    buffer = (unsigned char *)malloc(length / 4 * 3 + 4);
    if (buffer == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }

    for (index = 0; index < length; index++) {
        char digit = base64[index];
        int value;

        if (digit == '\n' || digit == '\r' || digit == ' ' || digit == '\t') {
            continue;
        }
        if (digit == '=') {
            padding++;
            continue;
        }
        if (padding > 0) {
            free(buffer);
            return STARKECDSA_ERROR_ENCODING;
        }
        value = valueFromBase64Digit(digit);
        if (value < 0) {
            free(buffer);
            return STARKECDSA_ERROR_ENCODING;
        }
        accumulator = (accumulator << 6) | (unsigned int)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buffer[target++] = (unsigned char)((accumulator >> bits) & 0xffu);
        }
    }

    if (padding > 2) {
        free(buffer);
        return STARKECDSA_ERROR_ENCODING;
    }

    *out = buffer;
    *outLength = target;
    return STARKECDSA_OK;
}
