/*
 * feodo_ip_blacklist.c
 *
 *  Created on: Aug 16, 2019
 *      Author: mfletche
 */

#define _XOPEN_SOURCE 500

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <string.h>

#define _WITH_GETLINE
#include <stdio.h>
#include <assert.h>

#include <errno.h>
#include <time.h>

#include "../utils/file_processing.h"
#include "ip_blacklist.h"

static const char *COMMENT_CHAR = "#";
static const char *FIRST_SEEN_DATETIME_FMT = "%Y-%m-%d %H:%M:%S";
static const char *LAST_ONLINE_DATE_FMT = "%Y-%m-%d";

#define TM_MON_APRIL 3
#define TM_MON_SEPTEMBER 8

/**
 * Fields of a Feodo blacklist file.
 */
struct feodo_row_s
{
    time_t first_seen;
    char *dst_ip;
    uint16_t dst_port;

    // last_online can be NULL
    time_t last_online;
    char *malware;
};

struct feodo_cb_data_s
{
    ip_blacklist *blacklist;
    int n_entries;	// Count of number entries added
};

typedef struct feodo_row_s feodo_row_t;
typedef struct feodo_cb_data_s feodo_cb_data_t;

/**
 * Callback for user to handle an IP address and port read from a blacklist
 * file.
 * @param ip_addr An IP address from a blacklist line.
 * @param port A port number from a blacklist line.
 * @param user_data User data passed in through the
 * process_firehol_blacklist_file function.
 */
typedef void (*handle_ip_port)(uint32_t ip_addr, uint16_t port, void *user_data);

/**
 * Searches for the comment character within a line. Returns non-zero if the
 * comment character is found.
 *
 * ASSUMPTION: No lines in the current Feodo file contain a comment character
 * after a line with information we want to parse.
 */
int
contains_comment(char *line)
{
    char *comment_start = NULL;
    if (!line) return 0;

    comment_start = strstr(line, COMMENT_CHAR);

    return (comment_start != NULL);
}

/**
 * Parse the first_seen datetime field from the Feodo blacklist into a time_t
 * variable.
 * @param field The field containing the datetime
 * @param result Variable to write result to
 * @return 0 if successful
 */
int
parse_first_seen_datetime(char *field, time_t *result)
{
    char *str_rc = NULL;
    struct tm first_seen;
    time_t temp;

    if (!field || !result) return -1;

    // Parse the datetime string and convert into time_t
    str_rc = strptime(field, FIRST_SEEN_DATETIME_FMT, &first_seen);
    if (!str_rc) return -1;

    // According to manpage for mktime, tm_isdst must be set explicitly
    // prior to calling mktime. UTC never uses DST.
    first_seen.tm_isdst = 0;
    temp = mktime(&first_seen);
    if (temp == (time_t)-1) return -1;
    *result = temp;

    return 0;
}

/**
 * Check if an IPv4 address is valid. Uses inet_pton but does not return the
 * result.
 * @param field The field containing the IPv4 address
 * @return True if address is valid.
 */
int
is_valid_ipv4_address(char *field)
{
    struct in_addr result;
    return (1 == inet_pton(AF_INET, field, &result));
}

/**
 * Parse the port from a field in a Feodo line.
 * @param field The field containing the port.
 * @return 0 if unsuccessful, or a port number.
 */
uint16_t
parse_port(char *field)
{
    long value;
    char *end;
    value = strtol(field, &end, 10);
    if (!value) return 0;

    // Check range
    if (value > 65535 || value < 0) return 0;

    return (uint16_t) value;
}

/**
 * Parses a date from the last_online field in a Feodo line.
 * @param field The field to parse.
 * @param result The variable to put the result in.
 * @return 0 if successful.
 */
int
parse_last_online(char *field, time_t *result)
{
    char *str_rc = NULL;
    struct tm last_online;
    time_t temp;

    if (!field || !result) return -1;

    memset(&last_online, 0, sizeof(last_online));

    // Parse the datetime string and convert into time_t
    str_rc = strptime(field, LAST_ONLINE_DATE_FMT, &last_online);
    if (!str_rc) return -1;
    temp = mktime(&last_online);
    if (temp == (time_t)-1) return -1;
    *result = temp;

    return 0;
}

/**
 * Parse a line from a Feodo file into a feodo_row_t struct.
 * @param parsed Address of a structure to hold the parsed values.
 * @param line The line to parse.
 * @return 0 if successful, -1 if an error occurred.
 */
int
parse_feodo_line(feodo_row_t *parsed, char *line)
{
    int rc;
    char *token = NULL;
    const char *delim = ",";

    if (!parsed || !line) return -1;

    memset(parsed, 0, sizeof(*parsed));
    if (contains_comment(line)) return 1;

    // first_seen
    token = strtok(line, delim);
    if (!token) return -1;
    rc = parse_first_seen_datetime(token, &parsed->first_seen);
    if (rc) return -1;

    // dst_ip
    token = strtok(NULL, delim);
    if (!token) return -1;
    if (!is_valid_ipv4_address(token)) return -1;
    parsed->dst_ip = strdup(token);
    if (!parsed->dst_ip) return -1;

    // port
    token = strtok(NULL, delim);
    if (!token) goto error;
    parsed->dst_port = parse_port(token);
    if (!parsed->dst_port) goto error;

    // last online
    token = strtok(NULL, delim);
    if (!token) goto error;
    rc = parse_last_online(token, &parsed->last_online);
    // last online can legitimately be NULL so failing to obtain the last
    // online value is not a failure to parse the whole line

    // malware family
    if (!rc)
    {
        // if previous token could not be parsed as a date, keep it for the
        // next parsing attempt
        token = strtok(NULL, delim);
        if (!token) goto error;
    }
    parsed->malware = strdup(token);
    if (!parsed->malware) goto error;

    return 0;

error:
    if (parsed->dst_ip) free(parsed->dst_ip);
    return -1;
}

int
parse_feodo_line_ip_only(feodo_row_t *parsed, char *line)
{
    assert(parsed);
    assert(line);

    // Truncate newline
    size_t line_len, line_idx;
    for (line_len = strlen(line); line_len > 0; line_len--)
    {
        line_idx = line_len - 1;
        if (line[line_idx] != '\r'
                && line[line_idx] != '\n')
            break;

        line[line_idx] = '\0';
    }

    memset(parsed, 0, sizeof(*parsed));
    if (!is_valid_ipv4_address(line)) return -1;
    parsed->dst_ip = strdup(line);
    if (!parsed->dst_ip) return -1;
    return 0;
}

/**
 * Convert an IPv4 address string to a 32-bit integer. Not in network-byte
 * order.
 * @param result Address of variable to store result.
 * @param ip_addr String containing the IP address.
 * @return 0 if successful.
 */
int
ip_addr_str_to_int(uint32_t *result, char *ip_addr)
{
    int rc;
    struct in_addr addr;

    if (!result || !ip_addr) return -1;

    rc = inet_pton(AF_INET, ip_addr, &addr);
    if (1 != rc) return -1;

    // Address is now in network byte order
    *result = (addr.s_addr >> 24)
            | ((addr.s_addr >> 16) & 0xFF) << 8
            | ((addr.s_addr >> 8) & 0xFF) << 16
            | (addr.s_addr & 0xFF) << 24;

    return 0;
}

int
insert_blacklist_item(ip_blacklist *bl, char *ip_addr, uint16_t port, char *malware_family)
{
    int rc;
    ip_key_value_t item;

    if (!bl || !ip_addr) return -1;

    rc = ip_addr_str_to_int(&item.ip_addr, ip_addr);
    if (rc) return -1;

    item.port = port;
    item.value.botnet_id = 0;

    rc = ip_blacklist_add(bl, &item);
    if (!rc) return -1;

    return 0;
}

void
handle_feodo_line(char *line, void *usr_data)
{
    int rc;
    feodo_cb_data_t *cb_data = (feodo_cb_data_t *)usr_data;
    feodo_row_t parsed;

    rc = parse_feodo_line_ip_only(&parsed, line);
    if (rc) return;

    rc = insert_blacklist_item(cb_data->blacklist, parsed.dst_ip,
            parsed.dst_port, parsed.malware);
    if (!rc) cb_data->n_entries++;

    free(parsed.malware);
    free(parsed.dst_ip);
}

/**
 * Bridge between getline and handle_feodo_line since if a line contains a NULL
 * character we don't want to bother reading past it.
 */
void
getline_feodo_cb(char *line, size_t line_sz, void *user_data)
{
    handle_feodo_line(line, user_data);
}

int
import_feodo_blacklist(char *path, ip_blacklist *bl)
{
    int n_lines;
    feodo_cb_data_t usr_data = {.blacklist = bl, .n_entries = 0};
    FILE *fp = fopen(path, "r");


    if (!fp) return -errno;

    n_lines = file_do_for_each_line(fp, getline_feodo_cb, &usr_data);
    fclose(fp);
    if (n_lines < 0) return n_lines;

    return usr_data.n_entries;
}
