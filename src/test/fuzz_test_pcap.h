/*
 * fuzz_test_pcap.h
 *
 *  Created on: 2/05/2019
 *      Author: mfletche
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
