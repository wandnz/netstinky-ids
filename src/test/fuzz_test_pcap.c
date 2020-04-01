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
#include "fuzz_test_pcap.h"

void fuzz_test_pcap(char *packet_file)
{
    assert(packet_file);

    // Open packet file
    struct packet_s test_packet;
    struct pcap_pkthdr pcap_hdr;

    FILE *fp = fopen(packet_file, "rb");
    if (NULL == fp)
    {
        perror("Could not open packet file");
        return;
    }

    test_packet = load_packet(fp, 1024);

    pcap_hdr.caplen = test_packet.size;
    pcap_hdr.len = test_packet.size;
    if (0 == gettimeofday(&(pcap_hdr.ts), NULL))
    {
        packet_handler(NULL, &pcap_hdr, test_packet.packet);
    }

    if (NULL != test_packet.packet) free(test_packet.packet);
}
