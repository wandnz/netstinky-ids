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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "domain_validation.h"


static inline int
is_valid_char(const char item)
{
    return (item == '-'
            || IN_RANGE(item, NUM_START, NUM_DIFF)
            || IN_RANGE(item, UPPER_START, UPPER_DIFF)
            || IN_RANGE(item, LOWER_START, LOWER_DIFF)
    );
}

int
is_domain_valid(const char *string, size_t domain_len)
{
    const char *label = NULL;
    unsigned int i;

    if (!string) return -1;
    if (!IN_RANGE(domain_len, MIN_LABEL_LEN, MAX_DOMAIN_LEN - MIN_LABEL_LEN))
    {
        return -1;
    }

    label = string;
    for (i = 0; i < domain_len; i++)
    {
        char m_char = string[i];
        size_t label_len = 0;

        // If we see a dot or a null byte, we have reached the end of a label
        if (m_char == '.' || m_char == '\0')
        {
            label_len = (string + i - label);  // ptr arithmetic
            if (label_len == 0) return -1;
            // Characters seen this far should have been valid, test length
            if (label_len > MAX_LABEL_LEN) return -1;
            // Characters and length are valid, start the next label
            label += label_len + 1;
        }
        else if (!is_valid_char(m_char)) return -1;
        // Current character is not a separator, null byte or invalid char,
        // so it will be added to the next label
    }

    // If we fall through, no errors have been detected
    return 0;
}
