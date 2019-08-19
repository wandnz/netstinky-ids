/*
 * urlhaus_domain_blacklist.c
 *
 *  Created on: 11/04/2019
 *      Author: mfletche
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include "domain_blacklist.h"
#include "urlhaus_domain_blacklist.h"
#include "ids_storedvalues.h"

struct urlhaus_cb_data_s
{
	domain_blacklist *blacklist;
	int n_entries;	// Count of number entries added
};

typedef struct urlhaus_cb_data_s urlhaus_cb_data_t;

/**
 * Return 1 if the line is a comment. Assumes that the '#' character is the first character in the
 * line (this has been true so far).
 *
 * @param line: A line from a urlhaus domain blacklist.
 */
int urlhaus_is_comment(char *line)
{
	assert(line);
	if (line[0] == '#') return 1;
	return 0;
}

void
handle_urlhaus_line(char *line, void *user_data)
{
	int rc;
	urlhaus_cb_data_t *data = (urlhaus_cb_data_t *)user_data;
	ids_ioc_value_t *value = NULL;

	if (!line) return;

	if (urlhaus_is_comment(line)) return;

	char *domain_name_pos = line + strlen("http://");
	if ('/' == *domain_name_pos) domain_name_pos++;	// Append extra in case prefix was 'https://'

	// Find first '/' character
	for (char *dn_iter = domain_name_pos; *dn_iter != '\0'; dn_iter++)
	{
		if ('/' == *dn_iter)
		{
			*dn_iter = '\0';
			break;
		}
	}

	// May overlap, so can't use strcpy or memmove.
	size_t domain_name_len = strlen(domain_name_pos);
	for (size_t it = 0; it <= domain_name_len; it++)
		line[it] = domain_name_pos[it];

	value = malloc(sizeof(*value));
	if (!value) return;
	value->botnet_id = 0;

	rc = domain_blacklist_add(data->blacklist, line, value);
	if (!rc)
	{
		free(value);
		return;
	}

	data->n_entries++;
}

/**
 * Bridge between getline and handle_urlhaus_line since if a line contains a NULL
 * character we don't want to bother reading past it.
 */
void
getline_urlhaus_cb(char *line, size_t line_sz, void *user_data)
{
	handle_urlhaus_line(line, user_data);
}

int
import_urlhaus_blacklist_file(char *path, domain_blacklist *bl)
{
	int n_lines;
	urlhaus_cb_data_t usr_data = {.blacklist = bl, .n_entries = 0};
	FILE *fp = fopen(path, "r");

	if (!fp) return -errno;

	n_lines = file_do_for_each_line(fp, getline_urlhaus_cb, &usr_data);
	if (n_lines < 0) return n_lines;

	return usr_data.n_entries;
}
