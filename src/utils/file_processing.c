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
#include "file_processing.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

int
file_do_for_each_line(FILE *fp, getline_handle_line_cb cb, void *usr_data)
{
    ssize_t rc;
    char *line = NULL;
    size_t line_sz = 0;
    int line_count = 0;

    if (!fp || !cb) return -1;

    // Run until EOF or an error occurs
    while (-1 != (rc = getline(&line, &line_sz, fp)))
    {
        line_count++;

        assert(rc >= 0);
        cb(line, (size_t)rc, usr_data);
    }

    if (line) free(line);

    // Was stop caused by EOF or an error?
    if (EINVAL == errno || ENOMEM == errno)
        return -errno;

    return line_count;
}
