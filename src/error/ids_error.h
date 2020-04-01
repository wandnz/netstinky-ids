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
 *
 */
#ifndef ERROR_IDS_ERROR_H_
#define ERROR_IDS_ERROR_H_

#include <stdlib.h>

#include <uv.h>

#define NSIDS_OK 0
#define NSIDS_CMDLN -1    // Could not parse command line arguments
#define NSIDS_MEM -2      // Could not allocate required memory
#define NSIDS_PCAP -3     // Error occurred within libpcap code
#define NSIDS_UV -4       // Error occurred within libuv code
#define NSIDS_MDNS -5     // Error within the Avahi code
#define NSIDS_SSL -6      // Error occurred within the SSL code
#define NSIDS_SIG -7

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
