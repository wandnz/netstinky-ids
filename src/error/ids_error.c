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
#include "ids_error.h"

const char *
check_uv_error(int uv_error)
{
    if (0 == uv_error) return NULL;
    return uv_strerror(uv_error);
}
