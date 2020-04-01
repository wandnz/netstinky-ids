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
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "../src/ids_event_list.h"

#include "CuTest.h"

struct ids_event_list
{
    struct ids_event *head;
    unsigned int max_events;
    unsigned int max_timestamps;
    unsigned int num_events;
};

struct ids_event_ts
{
    struct timespec tm_stamp;
    struct ids_event_ts *next;
};

struct ids_event
{
    struct ids_event_ts *times_seen;
    unsigned int num_times;
    char *iface;
    uint32_t src_ip;
    char *ioc;	/* may be a stringify-ed IP address or domain */
    struct ids_event *next;
    struct ids_event *previous;
};

void test_new_ids_event(CuTest *tc)
{
    struct in_addr ip_addr;
    char *iface = "eth0";
    char *ioc = "baddomain.com";

    inet_pton(AF_INET, "192.168.1.1", &ip_addr);
    struct ids_event *event = new_ids_event(
            iface,
            ntohl(ip_addr.s_addr),
            strdup(ioc));
    if (event) {
        /* The current time should be in the times_seen */
        CuAssertTrue(tc, event->times_seen != NULL);
        CuAssertTrue(tc, event->iface == iface);
        CuAssertTrue(tc, event->src_ip == ntohl(ip_addr.s_addr));
        CuAssertTrue(tc, strcmp(ioc, event->ioc) == 0);
        CuAssertTrue(tc, event->next == NULL);
        CuAssertTrue(tc, event->previous == NULL);

        free_ids_event(&event);
    }
}

void test_new_ids_event_list(CuTest *tc) {
    unsigned int max_events = 10;
    unsigned int max_timestamps = 20;

    /* Test general case */
    struct ids_event_list *list = new_ids_event_list(max_events, max_timestamps);
    if (list) {
        CuAssertTrue(tc, list->max_events == max_events);
        CuAssertTrue(tc, list->max_timestamps == max_timestamps);
        CuAssertTrue(tc, list->head == NULL);

        free_ids_event_list(&list);
    }
}

void test_ids_event_list_add_event(CuTest *tc) {
    struct ids_event *event = new_ids_event(
            "ether0",
            5000,
            strdup("domain.com"));
    struct ids_event *old_event;
    struct ids_event_list *list = new_ids_event_list(2, 2);

    if (event && list) {
        CuAssertTrue(tc, ids_event_list_add_event(list, event) == 1);
        CuAssertTrue(tc, list->head == event);

        old_event = event;
        event = new_ids_event("ether1", 200, strdup("baddomain.com"));
        if (event) {
            CuAssertTrue(tc, ids_event_list_add_event(list, event) == 1);
            CuAssertTrue(tc, list->head == event);
            CuAssertTrue(tc, list->head->next == old_event);
            CuAssertTrue(tc, list->head->next->previous == list->head);
        }

        /* This is the same type as the first event. */
        old_event = event;
        event = new_ids_event("ether0", 5000, strdup("domain.com"));
        if (event) {
            CuAssertTrue(tc, ids_event_list_add_event(list, event) == 1);
            CuAssertTrue(tc, strcmp(list->head->iface, "ether0") == 0);
            CuAssertTrue(tc, strcmp(list->head->ioc, "domain.com") == 0);
            CuAssertTrue(tc, list->head->next == old_event);
            CuAssertTrue(tc, list->head->next->previous == list->head);
            CuAssertTrue(tc, list->head->previous == NULL);

            /* There should be more than one timestamp */
            CuAssertTrue(tc, list->head->times_seen->next != NULL);
        }

        free_ids_event_list(&list);
    }
}

CuSuite *IdsEventListGetSuite()
{
    CuSuite* suite = CuSuiteNew();
    SUITE_ADD_TEST(suite, test_new_ids_event);
    SUITE_ADD_TEST(suite, test_new_ids_event_list);
    SUITE_ADD_TEST(suite, test_ids_event_list_add_event);

    return (suite);
}

