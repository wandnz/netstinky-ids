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
#ifndef SRC_TEST_FUZZ_TEST_PCAP_H_
#define SRC_TEST_FUZZ_TEST_PCAP_H_

#include <assert.h>
#include <stdio.h>
#include <sys/time.h>

#include <pcap.h>

#include "../ids_pcap.h"
#include "load_packet.h"

void fuzz_test_pcap(char *packet_file);

#endif /* SRC_TEST_FUZZ_TEST_PCAP_H_ */
