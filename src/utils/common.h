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
 * @brief Extremely common and very general functions and definitions.
 */

#include <config.h>

#include <stdio.h>
#include <string.h>

/**
 * Prints a message if DEBUG is defined. This is not very secure as
 * it allows the user to put in an arbitrary format string
 */
#define DPRINT(...) do { fprintf(stdout, __VA_ARGS__); } while (0)

/**
 * Malloc a structure when the size of the allocation is the same as the size
 * of the structure referenced by \p ptr
 */
#define MALLOC(ptr) do { ptr = malloc(sizeof(*ptr)); } while (0)

/**
 * Malloc a structure and zero it when the size of the allocation is the same
 * as the size of the structure referenced by \p ptr
 */
#define MALLOC_ZERO(ptr) do { ptr = malloc(sizeof(*ptr)); \
    if (ptr) memset(ptr, 0, sizeof(*ptr)); } while (0)

/**
 * Set the memory pointed to by \p ptr to 0 / NULL
 */
#define ZERO(ptr) do { memset(ptr, 0, sizeof(*(ptr))); } while (0);

#ifndef UTILS_COMMON_H_
#define UTILS_COMMON_H_

/* -- STRUCTURES -- */

/**
 * It is more efficient on ARM architecture to access arrays by pointer rather
 * than index. This allows a beginning/ending pointer pair to be returned from
 * a function
 */
struct ptr_range
{
    void *start;
    void *end;
};

#endif /* UTILS_COMMON_H_ */
