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
#include "sortedarray.h"

struct SortedArray
{
    void *_arr;
    unsigned int _n;    // number of items currently in array
    size_t _a_sz;       // memory allocated for array (in bytes)
    size_t _e_sz;       // size of each element
    bool _srtd;           // true if sorted
    
    cmpElement _cmp;
};

SortedArray *
sa_initialize(size_t elementSize, cmpElement cmp)
{
    assert(elementSize);
    assert(cmp);
    
    struct SortedArray *sa = malloc(sizeof(struct SortedArray));
    
    if (sa)
    {
        sa->_arr = NULL;
        sa->_n = 0;
        sa->_a_sz = 0;
        sa->_srtd = true;
        
        sa->_e_sz = elementSize;
        
        sa->_cmp = cmp;
    }
    
    return sa;
}

size_t
sa_get_size_of_elements(SortedArray *sa, unsigned int numElements)
{
    return numElements * sa->_e_sz;
}

unsigned int
sa_get_element_capacity(SortedArray *sa)
{
    assert(sa);
    
    return (unsigned int) (sa->_a_sz / sa->_e_sz);
}

/**
 * This version will take an index that is within the capacity of the array so
 * not all addresses returned will contain valid items.
 * @param sa
 * @param index
 * @return 
 */
void *
_get_element(SortedArray *sa, unsigned int index)
{
    assert(sa);
    assert(index < sa_get_element_capacity(sa));
    
    void *e = NULL; // pointer to element
    
    if (sa->_arr != NULL)
    {
        uint8_t *ba = (uint8_t *)sa->_arr + sa_get_size_of_elements(sa, index);
        e = ba;
    }
    
    return e;
}

void *
sa_get_element(SortedArray *sa, unsigned int index)
{
    assert(sa);
    assert(index < sa_get_number_of_elements(sa));
    
    return _get_element(sa, index);
}

bool
sa_has_capacity(SortedArray *sa, unsigned int numElements)
{
    assert(sa);
    
    return sa_get_element_capacity(sa) > numElements;
}

unsigned int
sa_get_number_of_elements(SortedArray *sa)
{
    assert(sa);
    
    return sa->_n;
}

bool
sa_set_array_size(SortedArray *sa, size_t sz)
{
    assert(sa);
    
    // don't "drop" valid items
    if (sz < (sa_get_size_of_elements(sa, sa->_n)))
        return false;
    
    void *np = realloc(sa->_arr, sz);   // new pointer
    if (np)
    {
        sa->_arr = np;
        sa->_a_sz = sz;
    }
    else
        return false;
    
    return true;
}

SA_INDEX
sa_insert_element(SortedArray *sa, void *element)
{
    assert(sa);
    assert(element);
    
    if (!sa->_arr || !sa_has_capacity(sa, sa->_n + 1))
    {
        if (!sa_set_array_size(sa, sa_get_size_of_elements(sa, sa->_n + ALLOC_NUM)))
            return -1;
    }
    
    void *ne = _get_element(sa, sa->_n);  // address of new element
    memmove(ne, element, sa->_e_sz);
    sa->_srtd = false;
    
    return sa->_n++;
}

void
sa_remove_element(SortedArray *sa, unsigned int index)
{
    assert(sa);
    assert(index < sa->_n);
    
    // if removed element is not last element, shift later elements over it
    if (sa->_n - index > 1)
    {
        size_t sz = sa_get_size_of_elements(sa, sa->_n - index - 1);   // size of mem to move
        memmove(sa_get_element(sa, index), sa_get_element(sa, index + 1), sz);
    }
    
    sa->_n--;
}

bool sa_quicksort(SortedArray *sa)
{
    assert(sa != NULL);
    
    if (sa->_srtd == true)
        return true;
    
    bool s = quicksort(sa->_arr, sa->_e_sz, sa->_cmp, 0, sa->_n - 1);
    
    if (s)
        sa->_srtd = true;
    
    return s;
}

SA_INDEX
sa_binary_search(SortedArray *sa, void *element)
{
    assert(sa);
    assert(element);
    
    if (!sa->_srtd)
        sa_quicksort(sa);
    
    long m = 0; // middle index
    
    if (sa->_arr && sa->_n)
    {
        long l, r;   // left, right indexes
        l = 0;
        r = sa->_n - 1;

        while (l <= r)
        {
            m = l + (r - l) / 2;
            int cmp = sa->_cmp(sa_get_element(sa, (int) m), element);
            if (cmp < 0)
                l = m + 1;
            else if (cmp > 0)
                r = m - 1;
            else
                break;
        }
    }
    
    return (int) m;
}

bool
sa_contains_element(SortedArray *sa, void *element)
{
    unsigned int i = sa_binary_search(sa, element);
    
    return 0 == sa->_cmp(sa_get_element(sa, i), element);
}

void *
sa_lookup_element(SortedArray *sa, void *element)
{
    void *closest = NULL;

    if (!sa || !element) return NULL;

    // Find closest match
    unsigned int idx = sa_binary_search(sa, element);
    closest = sa_get_element(sa, idx);

    // Exact match?
    if (0 == sa->_cmp(closest, element))
        return closest;

    return NULL;
}

size_t
sa_get_array_size(SortedArray *sa)
{
    return sa->_a_sz;
}

size_t
sa_get_element_size(SortedArray *sa)
{
    return sa->_e_sz;
}

bool
sa_is_sorted(SortedArray *sa)
{
    return sa->_srtd;
}

cmpElement
sa_compare(SortedArray *sa)
{
    return sa->_cmp;
}

void *
sa_free(SortedArray *sa, freeElement e_free)
{
    assert(sa);

    int i;

    if (sa)
    {
        // free elements first
        if (e_free != NULL)
        {
            for (i = 0; i < sa->_n; i++)
            {
                e_free(sa_get_element(sa, i));
            }
        }

        if (sa->_arr) free(sa->_arr);
        free(sa);
    }
    
    return NULL;
}
