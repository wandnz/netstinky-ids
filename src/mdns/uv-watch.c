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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <avahi-common/llist.h>
#include <avahi-common/malloc.h>
#include <avahi-common/timeval.h>

#include "uv-watch.h"

static void watch_update(AvahiWatch *w, AvahiWatchEvent event);
static void timeout_update(AvahiTimeout *t, const struct timeval *tv);

struct AvahiWatch {
    AvahiUvPoll *uv_poll;

    uv_poll_t handle;
    int fd;
    int in_callback; // boolean

    AvahiWatchCallback callback;
    AvahiWatchEvent last_event;
    void *userdata;

    AVAHI_LLIST_FIELDS(AvahiWatch, watches);
};

struct AvahiTimeout {
    AvahiUvPoll *uv_poll;
    uv_timer_t timer;
    AvahiTimeoutCallback callback;
    void *userdata;

    AVAHI_LLIST_FIELDS(AvahiTimeout, timeouts);
};

struct AvahiUvPoll {
    AvahiPoll api;
    uv_loop_t *loop;
    void *userdata;

    AVAHI_LLIST_HEAD(AvahiWatch, watches);
    AVAHI_LLIST_HEAD(AvahiTimeout, timeouts);
};

// Utilities
static AvahiWatchEvent map_events_from_uv(int status, enum uv_poll_event event) {
    return
        (status < 0 ? AVAHI_WATCH_ERR : 0) |
        (event & UV_READABLE ? AVAHI_WATCH_IN : 0) |
        (event & UV_WRITABLE ? AVAHI_WATCH_OUT : 0) |
        (event & UV_DISCONNECT ? AVAHI_WATCH_HUP : 0);
}

static int map_events_to_uv(AvahiWatchEvent events) {
    // TODO: AVAHI_WATCH_ERR ???
    return
        (events & AVAHI_WATCH_IN ? UV_READABLE : 0) |
        (events & AVAHI_WATCH_OUT ? UV_WRITABLE : 0) |
        (events & AVAHI_WATCH_HUP ? UV_DISCONNECT : 0);
}

// Libuv and Avahi callbacks (which should be lambdas)
void on_timeout(uv_timer_t *handle) {
    AvahiTimeout *t = handle->data;
    t->callback(t, t->userdata);
}

void on_poll_event(uv_poll_t *handle, int status, int events) {
    AvahiWatch *w = (AvahiWatch *) handle->data;
    AvahiWatchEvent e = map_events_from_uv(status, events);
    w->last_event = e;
    w->in_callback = true;
    w->callback(w, w->fd, e, w->userdata);
    w->in_callback = false;
}

static void timeout_close_cb(uv_handle_t *handle) {
    AvahiTimeout *t = (AvahiTimeout *) handle->data;
    avahi_free(t);
}

static void poll_close_cb(uv_handle_t *handle) {
    AvahiWatch *w = (AvahiWatch *) handle->data;
    avahi_free(w);
}

// AvahiPoll callback integrations
static AvahiWatch *watch_new(const AvahiPoll *api, int fd, AvahiWatchEvent event, AvahiWatchCallback callback, void *userdata) {
    AvahiWatch *w;
    AvahiUvPoll *u;

    u = api->userdata;

    if (!(w = avahi_new(AvahiWatch, 1)))
        return NULL;

    w->uv_poll = u;
    w->callback = callback;
    w->userdata = userdata;

    w->fd = fd;
    w->in_callback = false;
    w->last_event = (AvahiWatchEvent) 0;
    uv_poll_init(u->loop, &w->handle, fd);
    w->handle.data = w;

    watch_update(w, event);

    AVAHI_LLIST_PREPEND(AvahiWatch, watches, u->watches, w);

    return w;
}

static void watch_update(AvahiWatch *w, AvahiWatchEvent event) {
    int uv_events = map_events_to_uv(event);
    uv_poll_start(&w->handle, uv_events, on_poll_event);
}

static AvahiWatchEvent watch_get_events(AvahiWatch *w) {
    return w->in_callback ? w->last_event : (AvahiWatchEvent) 0;
}

static void watch_free(AvahiWatch *w) {
    uv_poll_t *handle = &(w->handle);
    handle->data = w;

    AVAHI_LLIST_REMOVE(AvahiWatch, watches, w->uv_poll->watches, w);
    if (uv_is_active((uv_handle_t *) handle))
        uv_poll_stop(handle);
    if (!uv_is_closing((uv_handle_t *) handle))
        uv_close((uv_handle_t *) handle, poll_close_cb);
    else
        avahi_free(w);
}

static AvahiTimeout *timeout_new(const AvahiPoll *api, const struct timeval *tv, AvahiTimeoutCallback callback, void *userdata) {
    AvahiTimeout *t;
    AvahiUvPoll *u;
    uv_timer_t *handle;

    u = api->userdata;

    if (!(t = avahi_new(AvahiTimeout, 1)))
        return NULL;

    t->uv_poll = u;
    t->callback = callback;
    t->userdata = userdata;
    handle = &(t->timer);

    uv_timer_init(u->loop, handle);
    t->timer.data = t;

    timeout_update(t, tv);

    AVAHI_LLIST_PREPEND(AvahiTimeout, timeouts, u->timeouts, t);

    return t;
}

static void timeout_update(AvahiTimeout *t, const struct timeval *tv) {
    uv_timer_stop(&t->timer);
    if (tv) {
        uint64_t milliseconds = avahi_age(tv) / 1000;
        uv_timer_start(&t->timer, on_timeout, milliseconds, 0);
    }
}

static void timeout_free(AvahiTimeout *t) {
    uv_timer_t *handle = &(t->timer);
    uv_timer_stop(handle);
    handle->data = t;

    AVAHI_LLIST_REMOVE(AvahiTimeout, timeouts, t->uv_poll->timeouts, t);
    if (!uv_is_closing((uv_handle_t *) handle))
        uv_close((uv_handle_t *) handle, timeout_close_cb);
    else
        avahi_free(t);
}

// Linked list traversal functions
static void cleanup_timeouts(AvahiUvPoll *u) {
    AvahiTimeout *t, *next;

    for (t = u->timeouts; t; t = next) {
        next = t->timeouts_next;
        timeout_free(t);
    }
}

static void cleanup_watches(AvahiUvPoll *u) {
    AvahiWatch *w, *next;

    for (w = u->watches; w; w = next) {
        next = w->watches_next;
        watch_free(w);
    }
}

// Public functions
AvahiUvPoll *avahi_uv_poll_new(uv_loop_t *loop) {
    AvahiUvPoll *u;

    u = (AvahiUvPoll *) malloc(sizeof *u);
    u->loop = loop;

    u->api.watch_new = watch_new;
    u->api.watch_update = watch_update;
    u->api.watch_get_events = watch_get_events;
    u->api.watch_free = watch_free;

    u->api.timeout_new = timeout_new;
    u->api.timeout_free = timeout_free;
    u->api.timeout_update = timeout_update;

    u->api.userdata = u;

    AVAHI_LLIST_HEAD_INIT(AvahiWatch, u->watches);
    AVAHI_LLIST_HEAD_INIT(AvahiTimeout, u->timeouts);

    return u;
}

void avahi_uv_poll_free(AvahiUvPoll *u) {
    cleanup_timeouts(u);
    cleanup_watches(u);
    free(u);
}

const AvahiPoll *avahi_uv_poll_get(AvahiUvPoll *u) {
    assert(u);
    return &u->api;
}
