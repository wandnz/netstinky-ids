/*
 * load_packet.h
 *
 *  Created on: 2/05/2019
 *      Author: mfletche
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
