#include <stdlib.h>
#include <string.h>
#include "../internal.h"

static const char hexDigits[] = "0123456789abcdef";

void starkecdsaHexFromBytes(const unsigned char *bytes, size_t length, char *out)
{
    size_t index;
    for (index = 0; index < length; index++) {
        out[index * 2] = hexDigits[(bytes[index] >> 4) & 0x0fu];
        out[index * 2 + 1] = hexDigits[bytes[index] & 0x0fu];
    }
    out[length * 2] = '\0';
}

int starkecdsaAllocHexFromBytes(const unsigned char *bytes, size_t length, char **out)
{
    char *buffer = (char *)malloc(length * 2 + 1);
    if (buffer == NULL) {
        return STARKECDSA_ERROR_MEMORY;
    }
    starkecdsaHexFromBytes(bytes, length, buffer);
    *out = buffer;
    return STARKECDSA_OK;
}

static int valueFromHexDigit(char digit)
{
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    }
    if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    return -1;
}

/*
 * Accepts a shorter string than expectedLength and left-pads it with zeroes,
 * the way the sibling libraries treat a secret written without its leading
 * zero bytes. Rejects anything longer, or any non-hex character.
 */
int starkecdsaBytesFromHex(const char *hex, unsigned char *out, size_t expectedLength)
{
    size_t digits;
    size_t offset;
    size_t index;

    if (hex == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    digits = strlen(hex);
    if (digits % 2 != 0 || digits > expectedLength * 2) {
        return STARKECDSA_ERROR_ENCODING;
    }

    memset(out, 0, expectedLength);
    offset = expectedLength - digits / 2;
    for (index = 0; index < digits; index += 2) {
        int high = valueFromHexDigit(hex[index]);
        int low = valueFromHexDigit(hex[index + 1]);
        if (high < 0 || low < 0) {
            memset(out, 0, expectedLength);
            return STARKECDSA_ERROR_ENCODING;
        }
        out[offset + index / 2] = (unsigned char)((high << 4) | low);
    }
    return STARKECDSA_OK;
}

int starkecdsaCompareBytes(const unsigned char *left, const unsigned char *right, size_t length)
{
    size_t index;
    for (index = 0; index < length; index++) {
        if (left[index] != right[index]) {
            return left[index] < right[index] ? -1 : 1;
        }
    }
    return 0;
}

int starkecdsaIsZeroBytes(const unsigned char *value, size_t length)
{
    unsigned char accumulator = 0;
    size_t index;
    for (index = 0; index < length; index++) {
        accumulator |= value[index];
    }
    return accumulator == 0;
}
