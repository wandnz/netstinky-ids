#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "str.h"

char *empty_string(void)
{
    char *ptr = malloc(sizeof(char) * 1);
    *ptr = '\0';
    return ptr;
}

int split_string(const char character, const char *input, const size_t length,
                 char **header, char **value)
{
    int i;
    char *header_ptr;
    char *value_ptr;

    if (input == NULL)
        return -1;

    for (i = 0; i < length; i++){
        if (input[i] == character)
            break;
    }

    if (i >= length)
        return -1;  /* Character was not found in the string */

    /* Copy the first part of the string to `header' */
    header_ptr = malloc(sizeof(char) * (i + 1));
    memcpy( header_ptr, input, i );
    header_ptr[i+1] = '\0';

    i++; /* Skip the separator character */

    /* Copy the rest of the string to `value'. */
    value_ptr = malloc(sizeof(char) * (length - i + 1));
    memcpy( value_ptr, &input[i], length - i + 1);
    value_ptr[length-i] = '\0'; /* NULL out the last char */

    *header = header_ptr;
    *value = value_ptr;

    return 0;
}

int trim_leading_whitespace(char *const str, const size_t str_len)
{
    size_t index = 0;
    size_t new_size = 0;

    if (str == NULL) {
        return -1;
    }

    if (str_len == 0) {
        return 0;
    }

    /* Advance index past any whitespace characters */
    while (isspace((unsigned char) str[index])
            && index < str_len) index++;

    if (index == str_len) {
        /* All characters in the string are white-space. Set empty string. */
        str[0] = '\0';
        return 0;
    } else {
        // Move the bytes in the string back over the leading white space
        new_size = str_len - index + 1;
        memmove(str, str + index, new_size);
        return (int) new_size - 1;
    }
}

int trim_trailing_whitespace(char *const str, const size_t str_len)
{
    long index = str_len - 1;

    if (str == NULL) {
        return -1;
    }

    if (str_len == 0){
        return 0;
    }

    /* Regress index past any whitespace characters */
    while (isspace(str[index]) && index >= 0) index--;

    if (index == str_len - 1) {
        // There was no whitespace on the end of the string. Do nothing.
        return (int) str_len;
    } else {
        // Set the byte after the current one to a NULL byte to signal the
        // end of the string
        assert(index + 1 > -1);
        assert(index + 1 < str_len);
        str[index + 1] = '\0';
        return (int) strnlen(str, str_len);
    }
}

