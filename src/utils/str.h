/*
 *
 * Copyright (c) 2020 The University of Waikato, Hamilton, New Zealand.
 *
 * This file is part of netstinky-ids.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-2-Clause
 *
 *
 */
#ifndef UTILS_H_
#define UTILS_H_
#include <stdlib.h>

/**
 * @brief Splits a string around the first instance of a character in the
 * string
 * 
 * The character buffers pointed to by `header' and `value' should be at least
 * `length' in size to ensure that there are no memory issues.
 * @param character the character to split around
 * @param input the input string
 * @param length the length of the input string
 * @param header pointer to a character buffer for storing the header (first)
 * string
 * @param value pointer to a character buffer for storing the value (second)
 * string
 * @return int returns 0 on success, -1 if there was an error or the character
 * was not found in the string
 */
int split_string(const char character, const char *input, const size_t length,
                 char **header, char **value);

/**
 * @brief Trim the leading whitespace from a string in buffer
 * 
 * @param str the source string to process (must be mutable)
 * @param str_len the string length of \p str
 * @return int the new length of the string (not including NULL byte), or -1
 * on error
 */
int trim_leading_whitespace(char *const str, size_t str_len);

/**
 * @brief Trim the trailing whitespace from a string in buffer
 * 
 * @param str the source string to process (must be mutable)
 * @param str_len the string length of \p str
 * @return int the new length of the string (not including NULL byte), or -1
 * on error
 */
int trim_trailing_whitespace(char *const str, size_t str_len);

/**
 * @brief Allocates an empty string on the heap
 * 
 * @return char* a pointer to the new string
 */
char *empty_string(void);
#endif
