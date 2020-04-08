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
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#include "logging.h"

static enum log_level current_log_level = L_ERROR;

void
set_log_level(enum log_level lvl)
{
    current_log_level = lvl;
}

void
logger(enum log_level lvl, const char *str, ... )
{
    va_list args;
    const char *lvl_str = NULL;
    FILE *log_file = stdout;

    if (current_log_level == L_NONE)
        return;
    if (lvl > current_log_level)
        return;

    switch (lvl)
    {
    case L_DEBUG:
        lvl_str = "debug";
        break;
    case L_INFO:
        lvl_str = "info";
        break;
    case L_WARN:
        lvl_str = "warn";
        break;
    case L_ERROR:
        lvl_str = "error";
        break;
    case L_NONE:
        // Unreachable, but silence warnings
        return;
    }

    va_start(args, str);

    // Intentionally omit \n to print prefix
    fprintf(log_file, "[%s] ", lvl_str);
    vfprintf(log_file, str, args);
    fprintf(log_file, "\n");
    fflush(log_file);

    va_end(args);
}
