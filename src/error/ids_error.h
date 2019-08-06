/*
 * ids_error.h
 *
 *  Created on: Jul 23, 2019
 *      Author: mfletche
 */

#ifndef ERROR_IDS_ERROR_H_
#define ERROR_IDS_ERROR_H_

#include <stdlib.h>

#include <uv.h>

#define print_error(error) do { \
	if (error) \
		fprintf(stderr, "%s %d: (%s) %s\n", __FILE__, __LINE__, __func__, error); \
	} while (0)

#define print_if_NULL(variable) do { \
	if (NULL == variable) \
	{ \
		fprintf(stderr, "%s %d: (%s) %s\n", __FILE__, __LINE__, __func__, #variable); \
	} \
	} while (0)

const char *
check_uv_error(int uv_error);

#endif /* ERROR_IDS_ERROR_H_ */
