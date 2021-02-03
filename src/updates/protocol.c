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
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "utils/logging.h"
#include "../blacklist/ids_storedvalues.h"
#include "../blacklist/domain_blacklist.h"
#include "ids_tls_update.h"
#include "uv_buf_helper.h"
#include "domain_validation.h"

// Labels for contents of each received line
static const char *dn_label = "DN_IOC:";
static const char *ip_label = "IP_IOC:";

static void
swap_blacklists(ids_update_ctx_t * const context)
{
    // Global blacklist pointers
    domain_blacklist **g_dn = context->domain;
    ip_blacklist **g_ip = context->ip;

    // Old blacklists
    domain_blacklist *old_dn = *g_dn;
    ip_blacklist *old_ip = *g_ip;
    // New blacklist pointers
    domain_blacklist *new_dn = context->new_domain;
    ip_blacklist *new_ip = context->new_ip;

    // NULL out the new pointers
    context->new_ip = NULL;
    context->new_domain = NULL;
    // Swap out the active blacklists
    *context->domain = new_dn;
    *context->ip = new_ip;

    // Free the old blacklists
    domain_blacklist_clear(old_dn);
    // free_domain_blacklist(dn);
    free_ip_blacklist(&old_ip);
}

static void
reinit_staging_blacklists(ids_update_ctx_t * const context)
{
    // For both blacklists:
    // - if the `new` blacklist is null, skip to CREATE
    // - if the `new` blacklist is non-null, but *is* the same as the active
    //   blacklist, skip to CREATE. Otherwise, free the blacklist.
    // - CREATE: create a new blacklist

    if (context->new_domain)
        if (*context->domain != context->new_domain)
            free_domain_blacklist(&context->new_domain);
    context->new_domain = new_domain_blacklist();

    if (context->new_ip)
        if(*context->ip != context->new_ip)
            free_ip_blacklist(&context->new_ip);
    context->new_ip = new_ip_blacklist();
}

static int
parse_ioc_update(const uv_buf_t *buf, tls_stream_t *stream);

ns_action_t
ns_cl_proto_on_handshake(ns_cli_state_t *state, tls_stream_t *stream)
{
    // Return NOP since will be waiting for version

    ns_action_t action = {.type = NS_ACTION_NOP, .send_buffer.base = NULL,
            .send_buffer.len = 0
    };

    if (!state || !stream) return action;

    return action;
}

int
ns_cl_proto_on_recv(ns_action_t *action, ns_cli_state_t *state,
        tls_stream_t *stream, const uv_buf_t *buf)
{
    int rc, parse_rc;

    action->type = NS_ACTION_NOP;
    action->send_buffer.base = NULL;
    action->send_buffer.len = 0;

    if (!state || !buf) return -1;

    switch(*state)
    {
    case NS_PROTO_VERSION_WAITING:
        // Received version, send operation
        action->send_buffer.base = malloc(1500);
        if (!action->send_buffer.base) return -1;

        action->type = NS_ACTION_WRITE;
        rc = snprintf(action->send_buffer.base, 1500, "OPERATION: UPDATE\n\n");
        assert(rc < 1500);
        action->send_buffer.len = rc;

        *state = NS_PROTO_OP_SENDING;
        break;
    case NS_PROTO_OP_SENDING:
        break;
    case NS_PROTO_IOCS_WAITING:
        // Process IOCs and send confirmation
        parse_rc = parse_ioc_update(buf, stream);
        if (parse_rc > 0)
        {
            // We have more IoCs coming. Don't change state
            break;
        }
        action->send_buffer.base = malloc(1500);
        if (!action->send_buffer.base) return -1;

        action->type = NS_ACTION_WRITE;
        if (parse_rc == 0)
            rc = snprintf(action->send_buffer.base, 1500,
                          "UPDATE CONFIRMED\n\n");
        else // parse_rc < 0
            rc = snprintf(action->send_buffer.base, 1500,
                          "ERROR\n\n");
        assert(rc < 1500);
        action->send_buffer.len = rc;

        *state = NS_PROTO_CONF_SENDING;
        break;
    case NS_PROTO_CONF_SENDING:
        break;
    case NS_PROTO_CLOSE:
        action->type = NS_ACTION_CLOSE;
        break;
    }

    return 0;
}

int
ns_cl_proto_on_send(ns_action_t *action, ns_cli_state_t *state,
        tls_stream_t *stream, int status __attribute__((unused)))
{
    ids_update_ctx_t *update_ctx = NULL;

    action->type = NS_ACTION_NOP;
    action->send_buffer.base = NULL;
    action->send_buffer.len = 0;

    if (!state)
    {
        logger(L_ERROR, "ns_cl_proto_on_send(): state was NULL");
        return -1;
    }

    switch(*state)
    {
    case NS_PROTO_VERSION_WAITING:
        break;
    case NS_PROTO_OP_SENDING:
        *state = NS_PROTO_IOCS_WAITING;

        // Prepare blacklist structures.
        update_ctx = stream->data;
        reinit_staging_blacklists(update_ctx);
        break;
    case NS_PROTO_IOCS_WAITING:
        break;
    case NS_PROTO_CONF_SENDING:
        // TODO: Begin close
        action->type = NS_ACTION_CLOSE;
        *state = NS_PROTO_CLOSE;
        update_ctx = stream->data;
        swap_blacklists(update_ctx);
        break;
    case NS_PROTO_CLOSE:
        logger(L_WARN, "NS_PROTO_CLOSE in on_send");
        break;
    }

    return 0;
}

/**
 * IP line is as follows:
 * "IP_IOC: <dotted quad>, <port>\n"
 *
 * This is a destructive method but currently no other operations need to be
 * performed on the line after this.
 */
static int
parse_ip_line(char *line, ip_key_value_t *ioc)
{
    int rc;
    char *token = NULL;
    char *delim = " ";
    uint32_t ip;
    uint32_t port;
    int quads[4];

    if (!line || !ioc) return -1;

    // First token is label (which was already checked)
    token = strtok(line, delim);
    if (!token) return -1;

    // Second token is IP address with trailing comma
    token = strtok(NULL, delim);
    if (!token) return -1;
    rc = sscanf(token, "%3d.%3d.%3d.%3d,", &quads[0], &quads[1], &quads[2],
            &quads[3]);
    if (rc < 4) return -1;

    // Convert quads into a 32 bit integer
    ip = (quads[0] << 24) | (quads[1] << 16) | (quads[2] << 8) | quads[3];

    // Third token is port
    token = strtok(NULL, delim);
    if (!token) return -1;
    rc = sscanf(token, "%5u", &port);
    if (rc < 1) return -1;

    // Check that there are no extra tokens
    token = strtok(NULL, delim);
    if (NULL != token) return -1;

    ioc->ip_addr = ip;
    ioc->port = port;

    // TODO: Include botnet ID
    ioc->value.botnet_id = 0;

    return 0;
}

/**
 * Domain line is as follows:
 * "DN_IOC: <domain>\n"
 *
 * This is a destructive method. Line should not be read after this function
 * has been run. The OUT variable should only be read prior to freeing LINE.
 *
 * Also allocates the value to be associated with the domain name. This will
 * write over whatever value was previously in the VALUE pointer, as it is
 * assumed that that address has been inserted into the hat-trie.
 */
static int
parse_dn_line(char *line, char **out, ids_ioc_value_t **value)
{
    char *delim = " ";
    char *token = NULL;
    char *domain = NULL;

    if (!line || !out) return -1;

    // First token is label, so discard
    token = strtok(line, delim);
    if (!token) return -1;

    // Second token is the domain name
    token = strtok(NULL, delim);
    if (!token || is_domain_valid(token, strlen(token)) != 0) return -1;
    domain = token;

    // Should be no further tokens
    token = strtok(NULL, delim);
    if (token) return -1;

    *out = domain;

    // TODO: Include real botnet value
    *value = new_ids_ioc_value(0);
    if (!*value) return -1;

    return 0;
}

static int
process_line(char *line, domain_blacklist **dn, ip_blacklist **ip)
{
    int rc;
    char *domain = NULL;

    // IP value will be copied into blacklist data structure but domain value
    // must be allocated and an address copied into the data structure.
    ip_key_value_t ioc;
    ids_ioc_value_t *domain_value = NULL;

    if (!line || !dn || !ip) return -1;

    if (line != NULL && *line == '\0')
    {
        // Ignore an empty string (probably a packet boundary)
        return 0;
    }
    else if (0 == strncmp(dn_label, line, strlen(dn_label)))
    {
        rc = parse_dn_line(line, &domain, &domain_value);
        if (rc < 0)
        {
            free_ids_ioc_value(domain_value);
            return -1;
        }
        rc = domain_blacklist_add(*dn, domain, domain_value);
        if (rc < 0)
        {
            free_ids_ioc_value(domain_value);
            return -1;
        }
    }
    else if (0 == strncmp(ip_label, line, strlen(ip_label)))
    {
        rc = parse_ip_line(line, &ioc);
        if (rc < 0) return -1;
        rc = ip_blacklist_add(*ip, &ioc);
        if (rc < 0) return -1;
    }
    else
    {
        logger(L_DEBUG, "process_line(): bad line: %s", line);
        return -1;
    }

    return 0;
}

/**
 * Parse an update packet. The update may span multiple packets.
 * @returns 0 if successful, and the packet was the last update packet expected,
 * -ve if an error occurred, +ve if successful but more packets expected.
 */
static int
parse_ioc_update(const uv_buf_t *buf, tls_stream_t *stream)
{
    char *line = NULL;
    char *next_line = NULL;
    int rc;
    ids_update_ctx_t *update_ctx = NULL;

    if (!buf || !stream)
        return -1;

    update_ctx = (ids_update_ctx_t *)stream->data;
    next_line = buf->base;

    do
    {
        // Iterate through each line in the buffer
        rc = uv_buf_read_line(buf, next_line, &line, &next_line);
        if (rc < 0) break;
        if (!next_line)
        {
            if (line) free(line);
            break;
        }

        // Check for end of update (two new-lines in a row)
        if (line && (*next_line == '\n' || *next_line == '\0')) {
            free(line);
            return 0;
        }

        rc = process_line(line, &update_ctx->new_domain, &update_ctx->new_ip);
        if (rc < 0)
            logger(L_WARN, "process_line(): bad line read");
        free(line);

    } while (next_line);

    return 1;
}
