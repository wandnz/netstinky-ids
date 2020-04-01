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
#ifndef SRC_TEST_LOAD_PACKET_H_
#define SRC_TEST_LOAD_PACKET_H_

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Represents a packet with SIZE valid bytes. PACKET is NOT null-terminated,
 * and is probably a dynamically allocated array of bytes.
 */
struct packet_s
{
    size_t size;
    uint8_t *packet;
};

struct packet_s
load_packet(FILE *fp, size_t max_bytes);

#endif /* SRC_TEST_LOAD_PACKET_H_ */
