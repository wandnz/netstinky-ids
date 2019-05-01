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

#include "urlhaus_domain_blacklist.h"

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

/**
 * Change the contents of the LINE buffer to be the domain name only. Does not resize the buffer.
 */
int
urlhaus_process_line(char **line, size_t *line_sz)
{
	assert(line);
	assert(*line);
	assert(line_sz);
	assert(*line_sz);

	if (urlhaus_is_comment(*line)) return 0;

	char *domain_name_pos = *line + strlen("http://");
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
		(*line)[it] = domain_name_pos[it];

	return 1;
}

/**
 * Return a pointer to a string which contains the next domain in a urlhaus file. Will return a
 * NULL pointer if the EOF is reached or an error occurs.
 *
 * @param fp: The current file pointer.
 * @return A pointer to a dynamically allocated string containing the domain name, or NULL if no
 * more domains could be found.
 */
char *
urlhaus_get_next_domain(FILE *fp)
{
	assert(fp);

	char *line = NULL;
	char *retval = NULL;
	size_t line_sz = 0;

	// Process lines until EOF/error or a valid domain is found
	while (-1 != getline(&line, &line_sz, fp))
	{
		if (urlhaus_process_line(&line, &line_sz))
		{
			retval = strdup(line);
			break;
		}
	}

	// Check if error occurred, or EOF
	if (NULL == retval)
	{
		int problem = errno;
		if (problem == 0 || problem == EINVAL || problem == ENOMEM)
		{
			if (errno != 0)
				perror("urlhaus_get_next_domain");
		}
	}

	free(line);
	return retval;
}
