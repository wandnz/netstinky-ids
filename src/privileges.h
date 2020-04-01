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
 * @brief Manage privileges / capabilities on a *nix OS.
 */

#ifndef PRIVILEGES_H_
#define PRIVILEGES_H_

/**
 * Uses setuid to change to a non-privileged user
 *
 * @param user system username
 * @param group system group-name (set to NULL to not change group)
 *
 * @returns 0 if successful, -1 on error
 *
 */
int
ch_user(const char *user, const char *group);

/**
 * Relinquish root privileges by changing to the given user and group
 * 
 * @param user system username
 * @param group system group-name
 *
 * @returns 0 if successful, -1 on error
 */
int
drop_root(const char *user, const char *group);

#endif
