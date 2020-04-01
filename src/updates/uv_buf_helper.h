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
#ifndef UV_BUF_HELPER_H_
#define UV_BUF_HELPER_H_

#include <uv.h>

/**
 * Dynamically allocate space and copy a line that starts from START in the
 * uv_buf. Will also provide the start location of the next line in the
 * NEXT_START variable.
 *
 * The line will be NULL terminated.
 *
 * If the operation is successful, but NEXT_START is NULL the EOF has been
 * reached.
 *
 * @param buf The buffer.
 * @param start The location of the start of the line.
 * @param line A variable which will hold the copy of the line.
 * @param next_start A variable which will contain the address of the first
 * character in the next line.
 * @returns 0 if successful or an error code if unsuccessful.
 *
 * If an error occurs, both LINE and NEXT_START will contain a NULL pointer.
 */
int
uv_buf_read_line(const uv_buf_t *buf, char *start, char **line,
        char **next_start);

#endif /* UV_BUF_HELPER_H_ */
