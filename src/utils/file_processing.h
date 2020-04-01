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
#ifndef SRC_UTILS_FILE_PROCESSING_H_
#define SRC_UTILS_FILE_PROCESSING_H_

#define _WITH_GETLINE
#include <stdio.h>
#include <stdlib.h>

/**
 * Callback for handling a line from a file separated into lines by the
 * getline() function.
 *
 * LINE should not be freed in this function, and should be copied if the
 * information is going to be retained.
 *
 * @param line The line retrieved by getline(). Should never be NULL.
 * @param line_len The number of bytes read from the file (excluding the final
 * NULL byte).
 * @param user_data A pointer to data provided by the user. May be NULL.
 */
typedef void (*getline_handle_line_cb)(char *line, size_t line_len,
        void *user_data);

/**
 * Run a callback function on each line that is extracted from a file.
 * @param fp The file to extract lines from.
 * @param cb The callback which will run on each line.
 * @param user_data User data which will be passed directly to the callback.
 * @returns The number of lines processed or an error code (-ve).
 */
int
file_do_for_each_line(FILE *fp, getline_handle_line_cb cb, void *usr_data);

#endif /* SRC_UTILS_FILE_PROCESSING_H_ */
