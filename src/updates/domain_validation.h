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
/** @file
 *
 */
#ifndef SRC_BLACKLIST_UPDATES_DOMAIN_VALIDATION_H_
#define SRC_BLACKLIST_UPDATES_DOMAIN_VALIDATION_H_

#define MAX_DOMAIN_LEN 253  ///< Maximum string length of a valid domain name
#define MAX_LABEL_LEN 63    ///< Maximum string length of a valid "label"
#define MIN_LABEL_LEN 1     ///< The minumum required number of labels
#define DELIMITER_CHAR "."  ///< The label separator to use

/**
 * @brief Optimized range-check for uints
 *
 * @param c The value to check
 * @param start The lower bound of the range
 * @param diff The difference from the lower bound to the upper bound
 */
#define IN_RANGE(c, start, diff) ((unsigned)(c - start) <= diff)

/*
 * The following constants are a micro-optimisation to make range checking
 * ASCII characters faster. When used with the IN_RANGE macro, a range check
 * can be done with a single comparison.
 */

#define NUM_START 0x30          ///< ASCII numeric range lower bound
#define NUM_DIFF 0x39 - 0x30    ///< ASCII numeric range difference

#define UPPER_START 0x41        ///< ASCII upper-case range lower bound
#define UPPER_DIFF 0x5A - 0x41  ///< ASCII upper-case range difference

#define LOWER_START 0x61        ///< ASCII lower-case range lower bound
#define LOWER_DIFF 0x7A - 0x61  ///< ASCII lower-case range difference

/**
 * Check if the given string is a well-formed domain name
 *
 * @param domain_name a null-terminated string containing the domain name
 * @param len the string length of \p domain_name
 * @returns 0 if successful or -ve value on failure
**/
int
is_domain_valid(const char *domain_name, const size_t len);

#endif /* SRC_BLACKLIST_UPDATES_DOMAIN_VALIDATION_H_ */
