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
 * @brief Standardized logging for the application
 */
#ifndef UTILS_LOGGING_H_
#define UTILS_LOGGING_H_

/**
 * @brief Enumeration of potential log levels
 *
 * Specifies the verbosity of the log output. Setting a higher level implies
 * that all levels below it will also be set
 */
enum log_level
{
    L_NONE = 0,
    L_ERROR = 1,
    L_WARN = 2,
    L_INFO = 3,
    L_DEBUG = 4
};

/**
 * @brief Set the log level for the entire application
 *
 * @param level the new log level to set
 */
void
set_log_level(enum log_level level);

/**
 * @brief Write a line to the log
 *
 * @param lvl the log level that this line will be written to
 * @param str the printf format string to print
 * @param ... extra arguments are passed to printf to be used with \ref str
 */
void
logger(enum log_level lvl, const char *str, ... );

#endif /* UTILS_LOGGING_H_ */
