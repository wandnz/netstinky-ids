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
 *
 */
#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

/**
 * Uses a struct so that the bytes can be copied within a single statement.
 */
typedef struct mac_addr
{
    uint8_t m_addr[6];
} mac_addr;

#endif /* SRC_COMMON_H_ */
