#include "ebvbl.h"

#define DIVIDEND_REMAINDER(dividend, remainder, i)          \
    dividend = i / 8;                                       \
    remainder = i % 8;

struct ebvbl
{
    uint8_t bff;    /* bit field factor: the number of bits to extract from
                    * the beginning of the IP address */
    uint8_t *bv;  /* bit vector */
    struct sorted_array *sa;
    
    element_fb fb;	/* function which extracts first n bits */
};

size_t
ebvbl_get_bit_vector_size(ebvbl_bff bff)
{
    assert(bff);
    unsigned int size_bits = (unsigned int)(1 << bff);
    unsigned int size_bytes = size_bits / 8;
    if (0 != size_bits % 8)
    	size_bytes++;
    return (size_bytes);
}

/**
 * Creates a bit vector of the correct size (rounded up to the nearest byte).
 * @param f The bit factor
 * @return A pointer to the bit vector, or NULL if allocation failed
 */
uint8_t *
ebvbl_bv_create(ebvbl_bff bff)
{
    assert(0 != bff);

    uint8_t *bv = calloc(1, ebvbl_get_bit_vector_size(bff));
    return (bv);
}

uint8_t
ebvbl_get_bit_at_index(struct ebvbl *e, element_prefix i)
{
    assert(NULL != e);
    assert(NULL != e->bv);
    assert(i < (ebvbl_get_bit_vector_size(e->bff) * 8));

    unsigned int byte_i, bit_i;
    DIVIDEND_REMAINDER(byte_i, bit_i, i);

    uint8_t mask = (1 << (7 - bit_i));
    uint8_t result = e->bv[byte_i] & mask;
    return (result);
}

bool
ebvbl_contains_element(struct ebvbl *e, element_ptr element)
{
    bool result = false;

    element_prefix p = e->fb(element, e->bff);
    uint8_t bit = ebvbl_get_bit_at_index(e, p);

    /* only perform search if bit was set which means there is at least one
     * element with the same prefix in the array */
    if (bit)
        result = sa_contains_element(e->sa, element);

    return (result);
}

struct ebvbl *
ebvbl_create(size_t element_size, element_cmp cmp, ebvbl_bff bff, element_fb fb,
		unsigned int element_realloc)
{
    assert(element_size > 0);
    assert(NULL != cmp);
    assert(bff > 0);
    assert(NULL != fb);
    
    struct ebvbl *e = malloc(sizeof(struct ebvbl));
    
    bool failure = false;
    
    /* allocate space for structures */
    if (!e)
        failure = true;
    else
    {
        e->sa = sa_create(element_size, cmp, element_realloc);
        if (!e->sa)
            failure = true;
        else
        {
            e->bv = ebvbl_bv_create(bff);
            
            if (!e->bv)
                failure = true;
            else
            {
                e->bff = bff;
                e->fb = fb;
            }
        }
    }
    
    /* if failure occurred, release anything that was allocated */
    if (failure)
    {
        if (NULL != e)
        {
            if (NULL != e->sa)
                free(e->sa);
            
            if (NULL != e->bv)
                free(e->sa);
            free(e);
            e = NULL;
        }
    }
    
    return (e);
}

void
ebvbl_free(struct ebvbl **e, element_free e_free)
{
    assert(NULL != e);
    assert(NULL != *e);
    /* e_free can be NULL */

    if (NULL != (*e)->sa)
        sa_free(&((*e)->sa), e_free);

    if (NULL != (*e)->bv)
        free((*e)->bv);

    free(*e);
    *e = NULL;
}

ebvbl_bff
ebvbl_get_bit_field_factor(struct ebvbl *ebvbl)
{
    assert(NULL != ebvbl);

    return (ebvbl->bff);
}

element_ptr
ebvbl_get_element(struct ebvbl *e, element_index index)
{
    assert(NULL != e);
    assert(NULL != e->sa);
    
    element_ptr ptr = sa_get_element(e->sa, index);
    return (ptr);
}

unsigned int
ebvbl_get_number_of_elements(struct ebvbl *e)
{
    assert(NULL != e);
    assert(NULL != e->sa);
    
    unsigned int num = sa_get_number_of_elements(e->sa);
    return (num);
}

unsigned int
_get_bv_index(struct ebvbl *e, void *element)
{
    unsigned int index = e->fb(element, e->bff);
    return index;
}

void
_set_bv_index(struct ebvbl *e, unsigned int i)
{
    assert(e);
    assert(e->bv);
    assert(i < ebvbl_get_bit_vector_size(e->bff));
    
    unsigned int byte_i, bit_i;
    DIVIDEND_REMAINDER(byte_i, bit_i, i);
    
    uint8_t mask = 1 << (7 - bit_i);
    e->bv[byte_i] |= mask;
}

void
_clear_bv_index(struct ebvbl *e, unsigned int i)
{
    assert(e);
    assert(e->bv);
    assert(i < ebvbl_get_bit_vector_size(e->bff));
    
    unsigned int byte_i, bit_i;
    DIVIDEND_REMAINDER(byte_i, bit_i, i);
    
    uint8_t mask = ~(1 << (7 - bit_i));
    e->bv[byte_i] &= mask;
}

ebvbl_result
ebvbl_insert_element(struct ebvbl *e, element_ptr element, size_t element_size)
{
    assert(NULL != e);
    assert(NULL != e->bv);
    assert(NULL != e->fb);
    assert(NULL != e->sa);
    assert(NULL != element);
    assert(element_size > 0);
    
    ebvbl_result result = EBVBL_FAILURE;

    sa_result sa_r = sa_insert_element(e->sa, element, element_size);
    if (SA_SUCCESS == sa_r)
    {
    	/* Set bit in bit vector */
        unsigned int bvi = _get_bv_index(e, element);
        _set_bv_index(e, bvi);
        result = EBVBL_SUCCESS;
    }
    else if (SA_FAILURE_MALLOC == sa_r)
    {
    	result = EBVBL_FAILURE_MALLOC;
    }

    return (result);
}

void
ebvbl_remove_element(struct ebvbl *e, element_index index)
{
	assert(NULL != e);
	/* Checks on index bounds will be performed by the sorted_array. */

	element_prefix prefix = e->fb(ebvbl_get_element(e, index), e->bff);

	/* Does it share a prefix with any other element? */
    bool shares_prefix = false;
    
    /* Check item before and item after to see if the element shares
     * a prefix with them. If not, the bit vector corresponding to
     * the prefix must be cleared. */
    if (index > 0)
    {
        element_prefix element_before = e->fb(ebvbl_get_element(e, index - 1), e->bff);
        if (element_before == prefix)
            shares_prefix = true;
    }
    
    if (!shares_prefix && index < (ebvbl_get_number_of_elements(e) - 1))
    {
        element_prefix element_after = e->fb(ebvbl_get_element(e, index + 1), e->bff);
        if (element_after == prefix)
            shares_prefix = true;
    }
    
    /* Do removal */
    sa_remove_element(e->sa, index);
    
    if (!shares_prefix)
        _clear_bv_index(e, prefix);
}
