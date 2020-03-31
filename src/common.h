/*
 * common.h
 *
 *  Created on: 29/04/2019
 *      Author: mfletche
 */

#ifndef SRC_COMMON_H_
#define SRC_COMMON_H_

// Uses a struct so that the bytes can be copied within a single statement.
typedef struct mac_addr
{
    uint8_t m_addr[6];
} mac_addr;

#endif /* SRC_COMMON_H_ */
