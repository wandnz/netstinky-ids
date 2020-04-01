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
#include "load_packet.h"

struct packet_s
load_packet(FILE *fp, size_t max_bytes)
{

    assert(fp);
    assert(max_bytes);

    struct packet_s result;

    result.size = 0;
    result.packet = NULL;

    result.packet = malloc(max_bytes);
    if (result.packet)
    {
        result.size = sizeof(uint8_t) * fread((void *)result.packet, sizeof(uint8_t), max_bytes, fp);
        if (0 == result.size)
        {
            // Read was unsuccessful
            free(result.packet);
            result.packet = NULL;
        }
        else
        {
            // If file was longer than MAX_BYTES invalidate result
            if (!feof(fp))
            {
                result.size = 0;
                free(result.packet);
                result.packet = NULL;
            }
        }
    }

    return result;
}
