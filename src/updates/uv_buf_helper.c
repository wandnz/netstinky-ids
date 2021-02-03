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
#include <stdlib.h>
#include <string.h>

#include "uv_buf_helper.h"

static int
is_addr_in(const uv_buf_t *buf, const char *start) {
    return !(start < buf->base || (buf->base + buf->len) <= start);
}

int
uv_buf_read_line(const uv_buf_t *buf, char *start, char **line,
        char **next_start)
{
    char *end;
    char *iter;
    size_t len;

    // NEXT_START can be NULL but the rest of the operation cannot continue
    // if any other argument is NULL.
    if (!buf || !start || !line) return -1;

    if (!is_addr_in(buf, start)) return -1;

    // Actually the first address that is invalid
    end = buf->base + buf->len;

    for (iter = start; iter < end; iter++)
    {
        // Detect end of line
        if ('\n' != *iter) continue;
        *next_start = iter + 1;
        len = *next_start - start;
        if (*next_start == end)
            *next_start = NULL;

        // Allocate some memory
        *line = malloc(len);
        if (!*line) return -1;

        // Copy and write a NULL terminator over the newline
        memcpy(*line, start, len);
        (*line)[len - 1] = '\0';

        return len;
    }

    // Reached end of buffer
    *next_start = NULL;
    len = end - start;

    // Reserve additional space for new line because will not write over
    // newline
    *line = malloc(len + 1);
    if (!*line) return -1;

    memcpy(*line, start, len);
    (*line)[len] = '\0';

    return len;
}
