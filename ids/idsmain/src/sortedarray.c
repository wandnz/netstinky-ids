#include "sortedarray.h"

struct sorted_array
{
    element_ptr array;
    unsigned int element_num;	/* Number of items currently in
    							 * the array. */
    unsigned int element_alloc;	/* Number of elements to allocate
    							 * whenever reallocation is required. */
    size_t array_size;			/* Memory allocated for array (in
    							 * bytes). */
    size_t element_size;  		/* Size of each element. */
    bool is_sorted;				/* True if sorted */
    
    element_cmp cmp;
};

element_cmp
sa_compare(struct sorted_array *sa)
{
    return (sa->cmp);
}

bool
sa_contains_element(struct sorted_array *sa, element_ptr element)
{
    sa_result lookup_r = sa_lookup(NULL, sa, element);

    return (SA_SUCCESS == lookup_r);
}

struct sorted_array *
sa_create(size_t element_size, element_cmp cmp,
		unsigned int element_alloc)
{
    assert(element_size > 0);
    assert(NULL != cmp);
    assert(element_alloc > 0);
    
    struct sorted_array *sa = malloc(sizeof(struct sorted_array));
    
    if (NULL != sa)
    {
        sa->array = NULL;
        sa->element_num = 0;
        sa->array_size = 0;
        sa->is_sorted = true;
        sa->element_alloc = element_alloc;
        
        sa->element_size = element_size;
        
        sa->cmp = cmp;
    }
    
    return (sa);
}

void
sa_free(struct sorted_array **sa, element_free e_free)
{
	assert(NULL != sa);
	assert(NULL != *sa);
	/* e_free can be NULL */

	int i = 0;

    /* Free elements first, if required. */
    if (e_free != NULL)
    {
        for (i = 0; i < (*sa)->element_num; i++)
        {
            e_free(sa_get_element(*sa, i));
        }
    }

    free((*sa)->array);
    free(*sa);

    /* This is entire reason for using double-pointer. */
    *sa = NULL;
}

size_t
sa_get_array_size(struct sorted_array *sa)
{
    return (sa->array_size);
}

/*
 * Check that the current array size has the capacity for a certain
 * number of elements.
 * @param sa The sorted array.
 * @param num_elements The desired capacity.
 * @return True if there is enough space.
 */
unsigned int
sa_get_element_capacity(struct sorted_array *sa)
{
    assert(NULL != sa);

    unsigned int capacity = sa->array_size / sa->element_size;
    return (capacity);
}

/**
 * Used for working out the address of an element. Returns the number of
 * bytes that a given number of elements occupy.
 */
size_t sa_get_offset(struct sorted_array *sa, unsigned int element_number)
{
    size_t offset = element_number * sa->element_size;
    return (offset);
}

/**
 * This is not safe. It will check that the index is not out of
 * bounds of the allocated memory, but it will return addresses to
 * elements which are not filled yet -- these should not be read,
 * only written to.
 */
element_ptr
sa_get_element_unchecked(struct sorted_array *sa, element_index index)
{
	/* Can still check that the index is within the allocated area. */
	assert(index < sa_get_element_capacity(sa));

	element_ptr r = NULL;
    if (sa->array != NULL)
    {
        uint8_t *byte_addr = (uint8_t *)sa->array + sa_get_offset(sa, index);
        r = (element_ptr)byte_addr;
    }
    
    return (r);
}

/**
 * This is the SAFE version (for users). Values are checked and
 * element is safe to read.
 */
element_ptr
sa_get_element(struct sorted_array *sa,
		element_index index)
{
	assert(NULL != sa);
    assert(index < sa_get_number_of_elements(sa));

    element_ptr e = sa_get_element_unchecked(sa, index);
    assert(NULL != e);

    return (e);
}

size_t
sa_get_element_size(struct sorted_array *sa)
{
	assert(NULL != sa);
    return (sa->element_size);
}

unsigned int
sa_get_number_of_elements(struct sorted_array *sa)
{
    assert(NULL != sa);
    
    return (sa->element_num);
}

/*
 * Check that there is enough space in the array for the given number
 * of elements.
 * @param sa The sorted array.
 * @param element_num The number of elements
 * @param True if there is enough space for element_num elements.
 */
bool
sa_has_capacity(struct sorted_array *sa, unsigned int element_num)
{
    assert(NULL != sa);

    bool result = sa_get_element_capacity(sa) > element_num;
    return (result);
}

sa_result
sa_set_array_size(struct sorted_array *sa, size_t sz)
{
    assert(sa);
    /* There should still be space for existing elements. */
    if (sa->element_num > 0)
    	assert(sz >= sa_get_offset(sa, sz / sa->element_num));

    sa_result r = SA_FAILURE;
    void *np = realloc(sa->array, sz);
    if (NULL != np)
    {
        sa->array = np;
        sa->array_size = sz;
        r = SA_SUCCESS;
    }
    else
        r = SA_FAILURE_MALLOC;

    return (r);
}

sa_result
sa_insert_element(struct sorted_array *sa, element_ptr element,
		size_t element_size)
{
    assert(NULL != sa);
    assert(NULL != element);
    assert(element_size <= sa->element_size);

    sa_result r = SA_FAILURE;
    if (!sa->array || !sa_has_capacity(sa, sa->element_num + 1))
    {
    	sa_result array_size_r = sa_set_array_size(sa, sa_get_offset(sa, sa->element_num + sa->element_alloc));
    	if (SA_SUCCESS != array_size_r)
    	{
    		r = array_size_r;
    		return (r);
    	}
    }

    /* Unchecked because the new element address will be technically
     * out of bounds. */
    element_ptr new_element = sa_get_element_unchecked(sa, sa->element_num);

    /* Only move the bytes which have been specified. */
    memmove(new_element, element, element_size);
    sa->is_sorted = false;
    sa->element_num++;

    r = SA_SUCCESS;
    return (r);
}

sa_result
sa_lookup(element_index* out, struct sorted_array *sa, element_ptr element)
{
    assert(NULL != sa);
    assert(NULL != element);

    sa_result result = SA_FAILURE_NX;

    /* Ensure sortedness before beginning. */
    if (!sa->is_sorted)
        sa_quicksort(sa);
    
    long m = 0;	/* middle */
    
    if (NULL != sa->array && sa->element_num > 0)
    {
        long l, r;   /* left, right indexes */
        l = 0;
        r = sa->element_num - 1;

        while (l <= r)
        {
            m = l + (r - l) / 2;
            int cmp = sa->cmp(sa_get_element(sa, m), element);
            if (cmp < 0)
                l = m + 1;
            else if (cmp > 0)
                r = m - 1;
            else
            {
            	/* found it */
            	result = SA_SUCCESS;
            	/* out can be NULL if the index isn't required */
            	if (NULL != out)
            		*out = m;
                break;
            }
        }
    }
    
    return (result);
}

sa_result
sa_quicksort(struct sorted_array *sa)
{
	assert(NULL != sa);

	sa_result r = SA_FAILURE;
	if (sa->element_num > 0)
	{
		bool s = quicksort(sa->array, sa->element_size, sa->cmp, 0, sa->element_num - 1);
		if (s)
		{
			sa->is_sorted = true;
			r = SA_SUCCESS;
		}
	}
	else
		/* No elements is easy to sort. */
		r = SA_SUCCESS;

    return (r);
}

void
sa_remove_element(struct sorted_array *sa, element_index index)
{
    assert(NULL != sa);
    assert(index < sa_get_number_of_elements(sa));

    /* if removed element is not last element, shift later elements over it */
    if (sa->element_num - index > 1)
    {
    	/* Later elements in the array must be moved. memmove is safe
    	 * even if the source/dest overlap (which they likely will in
    	 * this case). */
        size_t sz = sa_get_offset(sa, sa->element_num - index - 1);
        memmove(sa_get_element(sa, index), sa_get_element(sa, index + 1), sz);
    }

    sa->element_num--;
}
