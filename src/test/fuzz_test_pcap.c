/*
 * fuzz_test_pcap.c
 *
 *  Created on: 2/05/2019
 *      Author: mfletche
 */

#include "fuzz_test_pcap.h"

void fuzz_test_pcap(char *packet_file)
{
	assert(packet_file);

	// Open packet file
	struct packet_s test_packet;
	struct pcap_pkthdr pcap_hdr;
	struct ids_pcap_fields fields;

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
