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
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "byte_array.h"

/* -- PRIVATE FUNCTION DECLARATIONS -- */

static inline uint16_t
byte_array_get_uint16(const uint8_t *array);

uint32_t
byte_array_get_uint32(const uint8_t *array);

static inline uint8_t *
byte_array_put_uint16(uint16_t value, uint8_t *out_ptr);

static inline uint8_t *
byte_array_put_uint32(uint32_t value, uint8_t *out_ptr);

/* -- PUBLIC FUNCTIONS -- */

uint8_t *
byte_array_read_uint16(uint16_t *out, const uint8_t *pos,
        const uint8_t *buffer_end)
{
    assert(out);
    assert(pos);
    assert(buffer_end);

    uint8_t *r = NULL;
    size_t sz = sizeof(*out);
    if (buffer_end - pos >= sz)
    {
        *out = byte_array_get_uint16(pos);
        r = (uint8_t *)(pos + sz);
    }

    return (r);
}

uint8_t *
byte_array_read_uint32(uint32_t *out, const uint8_t *pos,
        const uint8_t *buffer_end)
{
    assert(out);
    assert(pos);
    assert(buffer_end);

    uint8_t *r = NULL;
    size_t sz = sizeof(*out);
    if (buffer_end - pos >= sz)
    {
        *out = byte_array_get_uint32(pos);
        r = (uint8_t *)(pos + sz);
    }

    return (r);
}

uint8_t *
byte_array_write_uint16(uint16_t value, uint8_t *pos,
        const uint8_t *buffer_end)
{
    assert(pos);
    assert(buffer_end);

    uint8_t *r = NULL;

    if (buffer_end - pos >= sizeof(value))
        r = byte_array_put_uint16(value, pos);

    return (r);
}

uint8_t *
byte_array_write_uint32(uint32_t value, uint8_t *pos,
        const uint8_t *buffer_end)
{
    assert(pos);
    assert(buffer_end);

    uint8_t *r = NULL;

    if (buffer_end - pos >= sizeof(value))
        r = byte_array_put_uint32(value, pos);

    return (r);
}

/* -- PRIVATE FUNCTIONS -- */

static inline uint16_t
byte_array_get_uint16(const uint8_t *array)
{
    assert(NULL != array);

    uint8_t *pos = (uint8_t *)array;

    unsigned int result = ((*(pos++) & 0xFF) << 8);
    result |= ((*pos & 0xFF) << 0);

    return (result);
}

uint32_t
byte_array_get_uint32(const uint8_t *array)
{
    assert(NULL != array);

    uint32_t result = ((array[0] & 0xFF) << 24)
            | ((array[1] & 0xFF) << 16)
            | ((array[2] & 0xFF) << 8)
            | ((array[3] & 0xFF) << 0);

    return (result);
}

static inline uint8_t *
byte_array_put_uint16(uint16_t value, uint8_t *out_ptr)
{
    assert(NULL != out_ptr);

    *(out_ptr++) = (value >> 8) & (0xFF);
    *(out_ptr++) = value & (0xFF);

    return (out_ptr);
}

static inline uint8_t *
byte_array_put_uint32(uint32_t value, uint8_t *out_ptr)
{
    assert(NULL != out_ptr);

    *(out_ptr++) = (value >> 24) & 0xFF;
    *(out_ptr++) = (value >> 16) & 0xFF;
    *(out_ptr++) = (value >> 8) & 0xFF;
    *(out_ptr++) = value & 0xFF;

    return (out_ptr);
}
