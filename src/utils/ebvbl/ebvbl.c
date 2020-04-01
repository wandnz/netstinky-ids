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
#include <stdio.h>
#include "ebvbl.h"

#define DIVIDEND_REMAINDER(dividend, remainder, i)          \
    dividend = i / 8;                                       \
    remainder = i % 8;

struct EBVBL
{
    uint8_t _f;    // bit field factor: the number of bits to extract from
                        // the beginning of the IP address
    uint8_t *_bv;       // bit vector
    SortedArray *_sa;
    
    // required functions
    first_bits _fb;
};

unsigned int
ebvbl_get_bit_field_factor(EBVBL *ebvbl)
{
    assert(ebvbl);
    
    return ebvbl->_f;
}

unsigned int
ebvbl_get_bit_vector_radius(unsigned int f)
{
    assert(f);
    assert(f <= maxKeyLength);
    
    return (1 << (maxKeyLength - f));
}

unsigned int
ebvbl_get_bit_vector_size(unsigned int f)
{
    assert(f);
    assert(f <= maxKeyLength);
    
    return (1 << f);
}

/**
 * Creates a bit vector of the correct size (rounded up to the nearest byte).
 * @param f The bit factor
 * @return A pointer to the bit vector, or NULL if allocation failed
 */
uint8_t *
init_bv(unsigned int f)
{
    assert(f);
    assert(f <= maxKeyLength);
    
    unsigned int sz = ebvbl_get_bit_vector_size(f) / 8;
    
    if (ebvbl_get_bit_vector_size(f) % 8)
        sz++;
    
    uint8_t *bv = calloc(1, sz);    // clears all bits
    return bv;
}

EBVBL *
ebvbl_init(size_t elementSize, cmpElement cmp, unsigned int f, first_bits fb)
{
    assert(elementSize);
    assert(cmp);
    assert(f);
    assert(f <= maxKeyLength);
    assert(fb);
    
    EBVBL *e = malloc(sizeof(EBVBL));
    
    bool failure = false;
    
    // allocate space for structures
    if (!e)
        failure = true;
    else
    {
        e->_sa = sa_initialize(elementSize, cmp);
        if (!e->_sa)
            failure = true;
        else
        {
            e->_bv = init_bv(f);
            
            if (!e->_bv)
                failure = true;
            else
            {
                e->_f = f;
                e->_fb = fb;
            }
        }
    }
    
    // release any resources that were allocated
    if (failure)
    {
        if (e)
        {
            if (e->_sa)
                free(e->_sa);
            
            if (e->_bv)
                free(e->_sa);
            free(e);
            e = NULL;
        }
    }
    
    return e;
}

/**
 * Helper function for clearing a bit vector. WARNING: After running this, most functions will not
 * find any entries in the SortedArray even if they are still there.
 */
void
_ebvbl_clear_bv(EBVBL *e)
{
    assert(e);
    size_t sz_bytes = ebvbl_get_bit_vector_size(e->_f) / 8;
    memset(e->_bv, 0, sz_bytes);
}

void *
ebvbl_get_element(EBVBL *e, unsigned int index)
{
    assert(e);
    assert(e->_sa);
    
    return sa_get_element(e->_sa, index);
}

unsigned int
ebvbl_get_number_of_elements(EBVBL *e)
{
    assert(e);
    assert(e->_sa);
    
    return sa_get_number_of_elements(e->_sa);
}

unsigned int
_get_bv_index(EBVBL *e, void *element)
{
    unsigned int index = e->_fb(element, e->_f);
    return index;
}

void
_set_bv_index(EBVBL *e, unsigned int i)
{
    assert(e);
    assert(e->_bv);
    assert(i < ebvbl_get_bit_vector_size(e->_f));
    
    unsigned int byte_i, bit_i;
    DIVIDEND_REMAINDER(byte_i, bit_i, i);
    
    uint8_t mask = 1 << (7 - bit_i);
    e->_bv[byte_i] |= mask;
}

void
_clear_bv_index(EBVBL *e, unsigned int i)
{
    assert(e);
    assert(e->_bv);
    assert(i < ebvbl_get_bit_vector_size(e->_f));
    
    unsigned int byte_i, bit_i;
    DIVIDEND_REMAINDER(byte_i, bit_i, i);
    
    uint8_t mask = ~(1 << (7 - bit_i));
    e->_bv[byte_i] &= mask;
}

uint8_t
_get_bit_at_index(EBVBL *e, unsigned int i)
{
    assert(e);
    assert(e->_bv);
    assert(i < ebvbl_get_bit_vector_size(e->_f));
    
    unsigned int byte_i, bit_i;
    DIVIDEND_REMAINDER(byte_i, bit_i, i);
    
    uint8_t mask = (1 << (7 - bit_i));
    uint8_t result = e->_bv[byte_i] & mask;
    return result;
}

SA_INDEX
ebvbl_insert_element(EBVBL *e, void *element)
{
    assert(e);
    assert(e->_bv);
    assert(e->_fb);
    assert(e->_sa);
    assert(element);
    
    SA_INDEX i = sa_insert_element(e->_sa, element);
    if (-1 != i)
    {
        // set bit in bv
        unsigned int bvi = _get_bv_index(e, element);
        _set_bv_index(e, bvi);
    }
    
    return i;
}

void
ebvbl_remove_element(EBVBL *e, unsigned int index)
{
    // elements must be in order to check this
    if (!sa_is_sorted(e->_sa))
        sa_quicksort(e->_sa);
    
    unsigned int ip = e->_fb(ebvbl_get_element(e, index), e->_f);   // item prefix
    bool found = false;  // found another element with the same prefix?
    
    if (index > 0)
    {   // prior item prefix
        unsigned int pip = e->_fb(ebvbl_get_element(e, index - 1), e->_f);
        if (pip == ip)
            found = true;
    }
    
    if (index < (ebvbl_get_number_of_elements(e) - 1))
    {   // post item prefix
        unsigned int pip = e->_fb(ebvbl_get_element(e, index + 1), e->_f);
        if (pip == ip)
            found = true;
    }
    
    // if element at INDEX is the only item with the f-bit prefix left, clear
    // that bit in the bit vector
    sa_remove_element(e->_sa, index);
    
    if (!found)
        _clear_bv_index(e, ip);
}

bool
ebvbl_contains(EBVBL *e, void *element)
{
    bool result = false;
    
    unsigned int p = e->_fb(element, e->_f);
    uint8_t bit = _get_bit_at_index(e, p);
    
    // only perform search if bit was set which means there is at least one
    // element with the same prefix in the array
    if (bit)
        result = sa_contains_element(e->_sa, element);
    
    return result;
}

const void *
ebvbl_lookup(EBVBL *e, void *element)
{
    // Check bit vector
    unsigned int p = e->_fb(element, e->_f);
    uint8_t bit = _get_bit_at_index(e, p);

    // Only do lookup if bit vector indicates there might be a match
    if (bit)
        return sa_lookup_element(e->_sa, element);

    return NULL;
}

void
ebvbl_clear(EBVBL *e, freeElement free_item)
{
    assert(e);
    _ebvbl_clear_bv(e);

    // Save values stored in sorted array
    size_t element_sz = sa_get_element_size(e->_sa);
    cmpElement cmp = sa_compare(e->_sa);

    // Free and re-initialize SortedArray
    sa_free(e->_sa, free_item);
    e->_sa = sa_initialize(element_sz, cmp);
}

EBVBL *
ebvbl_free(EBVBL *e, freeElement e_free)
{
    assert(e);
    
    if (e->_sa != NULL)
        sa_free(e->_sa, e_free);
    
    if (e->_bv != NULL)
        free(e->_bv);
    
    free(e);
    
    return NULL;
}

bool
ebvbl_sort(EBVBL *e)
{
    assert(e != NULL);
    assert(e->_sa != NULL);
    
    return sa_quicksort(e->_sa);
}
