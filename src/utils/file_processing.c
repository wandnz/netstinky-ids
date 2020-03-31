/*
 * file_processing.c
 *
 *  Created on: Aug 19, 2019
 *      Author: mfletche
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
