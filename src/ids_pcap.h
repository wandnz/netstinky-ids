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
 * @brief Sets up packet capture for an IDS.
 */

#ifndef IDS_PCAP_H_
#define IDS_PCAP_H_

#include <uv.h>

#include "common.h"
#include "ids_event_list.h"
#include "blacklist/domain_blacklist.h"
#include "blacklist/ip_blacklist.h"

/** Packet fields relevant to IoC detection */
struct ids_pcap_fields
{
    /** IPv4 source address */
    uint32_t src_ip;
    /** IPv4 destination address */
    uint32_t dest_ip;
    /** MAC address of the source device */
    mac_addr src_mac;
    /** MAC address of the destination device */
    mac_addr dest_mac;
    /** TCP/UDP port of the source */
    uint16_t src_port;
    /** TCP/UDP port of the destination */
    uint16_t dest_port;
    /** The domain name of the DNS query (if applicable, otherwise NULL) */
    char *domain;
    /** Interface name of the generating interface (currently not set) */
    char *iface;
};

/**
 * @brief Configure a pcap context with a filter on a network interface
 *
 * Create and activate a pcap on \p dev then set the filter to \p filter .
 * Also get a `selectable' file descriptor such that reads from pcap can be
 * done asynchronously.
 *
 * @param[out] pcap A pointer to a pcap_t pointer that will be set to the
 * initialized handle
 * @param filter A string containing a BPF to use when filtering captured
 * packets
 * @param dev A string containing the name of a local device to capture from
 * @return #NSIDS_OK on success or #NSIDS_PCAP on error
 */
int
configure_pcap(pcap_t **pcap, const char *filter, const char *dev);

/**
 * @brief Add a uv_poll_t task to the event loop to read from pcap
 *
 * Gets a selectable file-descriptor from \p pcap to use as the poll target of
 * a libuv uv_poll_t handle. When there is data available to the poll target,
 * a callback function will be called with a pointer to the new data.
 *
 * @param loop The event loop to add the task to
 * @param pcap_handle An un-initialized uv_poll_t handle to keep track of the
 * task on the event loop
 * @param pcap an active pcap_t context to extract the selectable file-
 * descriptor from
 */
int
setup_pcap_handle(uv_loop_t *loop, uv_poll_t *pcap_handle, pcap_t *pcap);

/**
 * Checks the domain name blacklist if a domain name is present in F, otherwise
 * checks the IP address blacklist.
 *
 * @param f The relevant fields from a packet capture
 * @param ip_bl The #ip_blacklist structure to check
 * @param dn_bl The #domain_blacklist structure to check
 * @return Address of the value associated with the IOC if the IOC is in the
 * blacklist, otherwise NULL
 */
const ids_ioc_value_t *
ids_pcap_is_blacklisted(struct ids_pcap_fields *f, ip_blacklist *ip_bl,
        domain_blacklist *dn_bl);

/**
 * @brief Attempt to compile and set \p filter on the context \p pcap
 *
 * @param pcap The pcap context to attach the filter to
 * @param filter The BPF filter to apply to packets
 * @param err A string buffer to write error messages \deprecated Unused
 */
int
set_filter(pcap_t *pcap, const char *filter, char *err);

/**
 * Puts fields from the incoming packet into an ids_pcap_fields structure. If
 * the packet was a DNS query, the query will be in the DOMAIN attribute.
 *
 * This does not change the IFACE attribute.
 * @param pcap_hdr The libpcap header of the read packet
 * @param pcap_data The data payload (including protocol headers) of the packet
 * @param out Pointer to a struct that will be populated with fields relating
 *            to the IDS status of this packet (listed or not)
 * @return 1 if reading was successful and the packet was one that we are
 * interested in, 0 if packet was not one we are interested in, -1 if there
 * was an error
 */
int
ids_pcap_read_packet(const struct pcap_pkthdr *pcap_hdr,
                     const unsigned char *pcap_data,
                     struct ids_pcap_fields *out);

/**
 * Packet handler callback for libpcap.
 */
void
packet_handler(unsigned char *user_dat,
               const struct pcap_pkthdr* pcap_hdr,
               const unsigned char *packet);

#endif /* IDS_PCAP_H_ */
