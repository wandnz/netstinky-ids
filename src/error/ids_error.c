/*
 * ids_error.c
 *
 *  Created on: Jul 23, 2019
 *      Author: mfletche
 */

#include "ids_error.h"

const char *
check_uv_error(int uv_error)
{
    if (0 == uv_error) return NULL;
    return uv_strerror(uv_error);
}
