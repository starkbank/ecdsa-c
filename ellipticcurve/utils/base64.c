/*
 * Base64 as RFC 4648 section 4, with padding. Tested against section 10.
 *
 * The decoder validates the quantum: a run of 4k+1 data characters has no
 * byte-string preimage and is rejected, padding may only complete a partial
 * quantum, nothing may follow it, and the bits left over in a partial quantum
 * must be zero. Otherwise one signature would have several accepted spellings,
 * which the Python reference does not allow either.
 */

#include <stdint.h>
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
        uint32_t triple = ((uint32_t)bytes[source] << 16)
                        | ((uint32_t)bytes[source + 1] << 8)
                        | (uint32_t)bytes[source + 2];
        buffer[target++] = alphabet[(triple >> 18) & 0x3fu];
        buffer[target++] = alphabet[(triple >> 12) & 0x3fu];
        buffer[target++] = alphabet[(triple >> 6) & 0x3fu];
        buffer[target++] = alphabet[triple & 0x3fu];
        source += 3;
    }

    if (length - source == 1) {
        uint32_t triple = (uint32_t)bytes[source] << 16;
        buffer[target++] = alphabet[(triple >> 18) & 0x3fu];
        buffer[target++] = alphabet[(triple >> 12) & 0x3fu];
        buffer[target++] = '=';
        buffer[target++] = '=';
    } else if (length - source == 2) {
        uint32_t triple = ((uint32_t)bytes[source] << 16) | ((uint32_t)bytes[source + 1] << 8);
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
    uint32_t accumulator = 0;
    int bits = 0;
    size_t target = 0;
    size_t index;
    size_t dataCharacters = 0;
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
        /* data after padding is not base64 */
        if (padding > 0) {
            free(buffer);
            return STARKECDSA_ERROR_ENCODING;
        }
        value = valueFromBase64Digit(digit);
        if (value < 0) {
            free(buffer);
            return STARKECDSA_ERROR_ENCODING;
        }
        dataCharacters++;
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buffer[target++] = (unsigned char)((accumulator >> bits) & 0xffu);
        }
    }

    /* the quantum: 4k data chars need no pad, 4k+2 need two, 4k+3 need one,
       and 4k+1 cannot occur */
    switch (dataCharacters % 4) {
    case 0:
        if (padding != 0) { free(buffer); return STARKECDSA_ERROR_ENCODING; }
        break;
    case 2:
        if (padding != 2) { free(buffer); return STARKECDSA_ERROR_ENCODING; }
        break;
    case 3:
        if (padding != 1) { free(buffer); return STARKECDSA_ERROR_ENCODING; }
        break;
    default:
        free(buffer);
        return STARKECDSA_ERROR_ENCODING;
    }
    /* leftover bits of a partial quantum must be zero, or two different
       strings decode to the same bytes */
    if (bits > 0 && (accumulator & ((1u << bits) - 1u)) != 0) {
        free(buffer);
        return STARKECDSA_ERROR_ENCODING;
    }

    *out = buffer;
    *outLength = target;
    return STARKECDSA_OK;
}
