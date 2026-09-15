#include <stdlib.h>
#include <string.h>
#include "../internal.h"

/*
 * Writing zeros over a buffer that is about to go out of scope is a dead store
 * the optimizer may delete. Calling memset through a volatile function pointer
 * forces the call to happen, on every compiler, at every optimization level.
 */
static void *(*volatile scrubImplementation)(void *, int, size_t) = memset;

void starkecdsaScrub(void *pointer, size_t length)
{
    if (pointer == NULL || length == 0) {
        return;
    }
    scrubImplementation(pointer, 0, length);
}

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
 * Reads hex the way int(string, 16) does in the Python reference: an odd digit
 * count means a leading half byte, and leading zero digits carry no value, so
 * "1", "01" and "0001" all denote the same secret. Anything that still does
 * not fit expectedLength bytes, or any non-hex character, is rejected.
 */
int starkecdsaBytesFromHex(const char *hex, unsigned char *out, size_t expectedLength)
{
    size_t digits;
    size_t offset;
    size_t index;
    size_t nibble = 0;

    if (hex == NULL || out == NULL) {
        return STARKECDSA_ERROR_ARGUMENT;
    }
    while (hex[0] == '0' && hex[1] != '\0') {
        hex++;
    }
    digits = strlen(hex);
    if (digits == 0 || digits > expectedLength * 2) {
        return STARKECDSA_ERROR_ENCODING;
    }

    memset(out, 0, expectedLength);
    offset = expectedLength - (digits + 1) / 2;
    /* an odd count: the first digit is the low nibble of the first byte */
    if (digits % 2 == 1) {
        int value = valueFromHexDigit(hex[0]);
        if (value < 0) {
            return STARKECDSA_ERROR_ENCODING;
        }
        out[offset] = (unsigned char)value;
        nibble = 1;
        offset++;
    }
    for (index = nibble; index < digits; index += 2) {
        int high = valueFromHexDigit(hex[index]);
        int low = valueFromHexDigit(hex[index + 1]);
        if (high < 0 || low < 0) {
            starkecdsaScrub(out, expectedLength);
            return STARKECDSA_ERROR_ENCODING;
        }
        out[offset + (index - nibble) / 2] = (unsigned char)((high << 4) | low);
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
