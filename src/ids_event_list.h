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
 * @brief A queue of recent events which have been detected by the IDS.
 *
 * The queue maintains a maximum number of events which is set at
 * initialization
 *
 * The events contain information about where they originated, on what
 * interface they were detected, indicator of compromise and time.
 */

#ifndef IDS_EVENT_LIST_H
#define IDS_EVENT_LIST_H

#include <stdint.h>

#include "common.h"
#include "utils/linked_list.h"
#include "blacklist/ids_storedvalues.h"

/**
 * @brief Information about an observed IoC event
 *
 * When an Indicator of Compromise is observed, this is called an "event". An
 * event is to be reported to a client device and as such, the details of
 * events are buffered in a linked-list (of which this struct is an element).
 */
struct ids_event
{
    /** a linked list of observation timestamps */
    struct ids_event_ts *times_seen;
    /** the number of times this IoC has been observed */
    unsigned int num_times;
    /** the interface name of the interface where the event was observed */
    char *iface;
    /** the IPv4 address of the generating device */
    uint32_t src_ip;
    /** the MAC address of the generating device */
    mac_addr mac;
    /** may be a stringify-ed IP address or domain */
    char *ioc;

    /** A copy of the value associated with the IOC. This is a copy since the
     * blacklist may change and the IOC/value pair may be removed but the event
     * should still be associated with the same botnet ID. */
    ids_ioc_value_t ioc_value;

    /** The next value of the list **/
    struct ids_event *next;
    /** the previous value of the list **/
    struct ids_event *previous;
};

/**
 * A linked-list containing #ids_event structures
 */
struct ids_event_list
{
    /** The head of the linked-list, or NULL for an empty list */
    struct ids_event *head;
    /** The maximum number of events to store in the list */
    unsigned int max_events;
    /** The maximum number of timestamps to store for repeated events */
    unsigned int max_timestamps;
    /** \deprecated Unused */
    unsigned int num_events;
};

/**
 * A linked-list of timestamps
 */
struct ids_event_ts
{
    /** The timestamp of this event */
    struct timespec tm_stamp;
    /** The next timestamp in the list, or NULL if no more timestamps */
    struct ids_event_ts *next;
};

/**
 * Free an ids_event structure and any further entries in the list.
 * @param e A pointer to the address of the first ids_event to free. May not be
 * NULL but can handle (*e) being NULL.
 */
void
free_ids_event(struct ids_event **e);

/**
 * @brief Free an #ids_event_list structure, including any #ids_event children
 *
 * All members of the list are freed alongside the list structure itself. The
 * pointer pointed to by \p list is also set to NULL.
 */
void
free_ids_event_list(struct ids_event_list **list);

/**
 * Free an ids_event_time structure and any further entries in the list.
 * @param t A pointer to the address of the first ids_event_time to free. May
 * not be NULL but can handle *T being NULL.
 */
void
free_ids_event_ts(struct ids_event_ts **t);

/**
 * Add an event to the front of the list. If E is added to the list it will be
 * cleaned up by a single call to free_ids_event on the head of the list.
 * Otherwise the caller is responsible for freeing E.
 * @param list Pointer to an ids_event_list struct. May not be NULL.
 * @param e The event to add to the list.
 * @return 1 if the event was added to the list, 0 if unsuccessful.
 */
int
ids_event_list_add_event(struct ids_event_list *list, struct ids_event *e);

/**
 * Checks if the ids_event list contains an event equivalent to E, and returns
 * the equivalent event if it was found.
 *
 * If an event is found, E should not be a new entry in the event list, but
 * should have its timestamp added to the list of ids_event_time associated
 * with the equivalent event.
 *
 * @param list The ids_event_list to search.
 * @param e The event to search for.
 * @return The address of an equivalent event.
 */
struct ids_event *
ids_event_list_contains(struct ids_event_list *list, struct ids_event *e);

/**
 * @brief Trim the oldest events in \p list until only
 * \ref ids_event_list.max_events remain.
 *
 * Will traverse \ref ids_event_list.max_events events into the list before
 * freeing the remaining events from the tail of the list.
 *
 * @param list The ids_event_list to traverse
 */
void
ids_event_list_enforce_max_events(struct ids_event_list *list);

/**
 * Creates a new IDS event with the attributes provided and a current
 * timestamp.
 * @param iface The name of the network interface which observed this event.
 * May not be NULL.
 * @param src_ip The IP of the device which generated this event.
 * @param ioc A string containing the indicator of compromise (a domain name or
 * a string-ified IP address). May not be NULL.
 * @param mac the MAC address of the device that generated this event
 * @param ioc_value The value stored in the blacklist for the particular IOC.
 * @return A pointer to a valid ids_event structure, or NULL if the ids_event
 * could not be created.
 */
struct ids_event *
new_ids_event(char *iface, uint32_t src_ip, char *ioc, mac_addr mac,
        ids_ioc_value_t ioc_value);

/**
 * Creates a new IDS event list with the given number of maximum events and
 * maximum timestamps. The least recent events and timestamps will be dropped
 * if the maximums would be exceeded.
 * @param max_events The maximum length of the list of events.
 * @param max_timestamps The maximum length of the list of timestamps in each
 * event.
 * @return A valid ids_event_list or NULL if the ids_event_list could not be
 * created.
 */
struct ids_event_list *
new_ids_event_list(unsigned int max_events, unsigned int max_timestamps);

/**
 * Gets a new ids_event_time struct which can be added to an ids_event.
 * @return A valid ids_event_time struct for the current time, or NULL if the
 * ids_event_time could not be created.
 */
struct ids_event_ts *
new_ids_event_ts(void);

#endif
