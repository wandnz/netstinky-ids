/*
 * ids_event_queue.c
 *
 *  Created on: 31/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <assert.h>

#include "ids_event_list.h"

/* Both of these structures are linked lists. */

/**
 * Add a timestamp to the front of a list of times.
 * @param list The address of a pointer to the head of the list. May not be
 * NULL but *list may be NULL.
 * @param tm The timestamp to add to the list.
 * @return 1 if successful, 0 if unsuccessful.
 */
int
ids_event_time_list_add(struct ids_event_list *list, struct ids_event *event,
        struct ids_event_ts *tm);

void
ids_event_time_list_enforce_max_timestamps(struct ids_event_list *list,
        struct ids_event_ts *tm_list);

void
free_ids_event(struct ids_event **e)
{
    assert(e);

    struct ids_event *event_iter = *e, *tmp;

    if (e && *e)
    {
        while (event_iter)
        {
            tmp = event_iter;
            event_iter = event_iter->next;

            free_ids_event_ts(&(tmp->times_seen));

            /* Interface names are from the command line and should not be
             * freed */

            if (tmp->ioc) free(tmp->ioc);

            free(tmp);
        }

        *e = NULL;
    }
}

void
free_ids_event_list(struct ids_event_list **list)
{
    assert(list);

    if (list && *list)
    {
        free_ids_event(&(*list)->head);
        free(*list);

        *list = NULL;
    }
}

void
free_ids_event_ts(struct ids_event_ts **t)
{
    assert(t);
    assert(*t);

    struct ids_event_ts *time_iter = *t, *tmp;

    if (t && *t)
    {
        while (time_iter)
        {
            tmp = time_iter;
            time_iter = time_iter->next;

            free(tmp);
        }

        *t = NULL;
    }
}

int
ids_event_list_add_event(struct ids_event_list *list, struct ids_event *e)
{
    assert(list);
    assert(e);

    struct ids_event *existing = NULL, *head = list->head;
    int result = 0;

    if (list && e)
    {
        if (NULL != (existing = ids_event_list_contains(list, e)))
        {
            /* Don't add a completely new entry, just add the timestamp to the
             * list inside the existing event */
            if (ids_event_time_list_add(list, existing, e->times_seen))
            {
                /* Move existing event to the front of the queue. */
                if (existing->previous)
                    existing->previous->next = existing->next;
                else
                    // Completely remove for now, to prevent a loop
                    list->head = existing->next;
                if (existing->next)
                    existing->next->previous = existing->previous;

                existing->previous = NULL;
                existing->next = list->head;

                list->head = existing;

                existing->num_times++;

                /* Most of the ids_event is no longer needed, but don't free
                 * the time */

                // Free IOC string since it's a duplicate
                free(e->ioc);
                free(e);
                result = 1;
            }
        }
        else
        {
            /* Add a new entry */
            if (list->head)
            {
                /* Add to head of list */
                list->head = e;
                e->next = head;
                head->previous = e;

                ids_event_list_enforce_max_events(list);
            }
            else
            {
                /* It's the first entry in the list */
                list->head = e;
            }
        }

        result = 1;
    }

    /* Could not add event because list wasn't initialized */
    else free_ids_event(&e);

    return (result);
}

void
ids_event_list_enforce_max_events(struct ids_event_list *list)
{
    assert(list);

    /* num_steps is number of next pointers to follow to get to tail */
    int i = 0, num_steps = list->max_events - 1;
    struct ids_event *tail;
    if (list)
    {
        tail = list->head;

        for (i = 0; i < num_steps; i++)
        {
            if (!tail) return;
            tail = tail->next;
        }

        if (!tail || !tail->next) return;
        /* Remove all events older than tail */
        free_ids_event(&(tail->next));
    }
}

int
ids_event_time_list_add(struct ids_event_list *list, struct ids_event *event,
        struct ids_event_ts *tm)
{
    assert(list);
    assert(event);
    assert(tm);

    int result = 0;

    if (list && event && tm)
    {
        tm->next = event->times_seen;
        event->times_seen = tm;

        ids_event_time_list_enforce_max_timestamps(list, event->times_seen);

        result = 1;
    }

    return (result);
}

void
ids_event_time_list_enforce_max_timestamps(struct ids_event_list *list,
        struct ids_event_ts *tm_list)
{
    assert(list);
    assert(tm_list);

    int iter;
    struct ids_event_ts *tail = tm_list;

    /* How many times to follow the next pointer */
    unsigned int num_steps = list->max_timestamps - 1;

    if (list && tm_list)
    {
        for (iter = 0; iter < num_steps; iter++)
        {
            if (!tail) return;
            tail = tail->next;
        }

        if (!tail || !tail->next) return;
        /* Remove all timestamps after tail */
        free_ids_event_ts(&(tail->next));
    }
}

/* Assumes:
 * -- iface is from command line arguments and does not need to
 * be freed
 * -- ioc is a duplicate and must be freed
 *
 * Will release IOC if cannot make a new event.
 */
struct ids_event *
new_ids_event(char *iface, uint32_t src_ip, char *ioc, mac_addr mac,
        ids_ioc_value_t ioc_value)
{
    assert(iface);
    assert(ioc);

    struct ids_event *e = NULL;
    struct ids_event_ts *t = NULL;

    if (iface && ioc)
    {
        if (!(e = malloc(sizeof(*e)))) goto error;
        if (!(t = new_ids_event_ts())) goto error;

        e->num_times = 1;
        e->times_seen = t;
        e->iface = iface;
        e->src_ip = src_ip;
        e->mac = mac;
        e->ioc = ioc;
        e->ioc_value = ioc_value;

        e->next = NULL;
        e->previous = NULL;
    }
    else goto error;

    return (e);

error:
    if (ioc) free(ioc);
    free_ids_event_ts(&t);
    free_ids_event(&e);
    return (NULL);
}

struct ids_event_list *
new_ids_event_list(unsigned int max_events, unsigned int max_timestamps)
{
    assert(max_events > 0);
    assert(max_timestamps > 0);

    struct ids_event_list *list = NULL;

    if (max_events > 0 && max_timestamps > 0)
    {
        if (NULL != (list = malloc(sizeof(*list))))
        {
            list->head = NULL;
            list->max_events = max_events;
            list->max_timestamps = max_timestamps;
        }
    }

    return (list);
}

struct ids_event *
ids_event_list_contains(struct ids_event_list *list, struct ids_event *e)
{
    assert(list);
    assert(e);

    struct ids_event *list_iter = NULL;
    struct ids_event *result = NULL;

    if (list && list->head && e)
    {
        list_iter = list->head;

        while (list_iter)
        {
            if (!strcmp(list_iter->iface, e->iface)
                    && (list_iter->src_ip == e->src_ip)
                    && !strcmp(list_iter->ioc, e->ioc))
            {
                result = list_iter;
                break;
            }

            list_iter = list_iter->next;
        }
    }

    return (result);
}

struct ids_event_ts *
new_ids_event_ts()
{
    struct ids_event_ts *tm = NULL;

    if ( !( tm = malloc( sizeof( *tm ) ) ) ) goto error;

    /* 0 indicates success, all errors are programmer errors */
    if ( -1 == clock_gettime( CLOCK_REALTIME, &( tm->tm_stamp ) ) )
    {
        assert(0);
        goto error;
    }

    tm->next = NULL;

    return ( tm );

error:
    free_ids_event_ts(&tm);
    return (NULL);
}
