/**
 * A sorted array implementation that can store any type of structure.
 */

#ifndef SORTED_ARRAY_H_
#define SORTED_ARRAY_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "quicksort.h"

/*
 * Used to indicate success or failure of functions.
 */
typedef enum
{
	SA_SUCCESS,
	SA_FAILURE,
	SA_FAILURE_OOB,		/* Index was out of bounds. */
	SA_FAILURE_MALLOC,	/* Malloc failed. */
	SA_FAILURE_NX		/* Something referred to a non-existent
						 * element. */
} sa_result;

struct sorted_array;

/*
 * Used to refer to elements in the sorted array.
 */
typedef void* element_ptr;
typedef unsigned int element_index;

typedef int (*element_cmp)(element_ptr a, element_ptr b);
typedef void (*element_free)(element_ptr a);

/**
 * Retrieve a pointer to the comparison function which the array is
 * using.
 * @param sa The sorted array.
 * @return A function pointer to the comparison function.
 */
element_cmp
sa_compare(struct sorted_array *sa);

/**
 * Returns true if the array contains the given element.
 * @param sa The sorted array.
 * @param element The element to lookup in the array.
 * @return True if an cmp() returns 0 when comparing the given
 * element with any element in the array.
 */
bool
sa_contains_element(struct sorted_array *sa, element_ptr element);

/**
 * Create a sorted_array structure with the provided element size,
 * comparison function and number of elements to allocate.
 * @param element_size The fixed size of each element in bytes.
 * Must be greater than zero.
 * @param cmp A function which will provide the relative order of
 * elements. Must not be NULL.
 * @param element_alloc The number of elements to allocate space for
 * each time a reallocation is required. Must be greater than zero.
 * @return The address of the sorted array, or NULL if memory
 * allocation failed.
 */
struct sorted_array*
sa_create(size_t element_size, element_cmp cmp,
		unsigned int element_alloc);

/**
 * Free a sorted array and all elements within it.
 * @param sa The address of the pointer to the sorted array struct.
 * This pointer will NULL after this function.
 * @param free A function which will free elements within the sorted
 * array. May be NULL if no additional cleanup is required.
 */
void
sa_free(struct sorted_array **sa, element_free e_free);

/**
 * Gets the address of the element at the given index.
 * @param sa The sorted array.
 * @param index The index of the element. Must be less than
 * sa_get_num_of_elements().
 * @return The address of the element.
 */
element_ptr
sa_get_element(struct sorted_array *sa, element_index index);

/**
 * Get the amount of bytes allocated to each element in the array.
 * @param sa The sorted array.
 * @return The amount of bytes allocated to each element in the
 * array.
 */
size_t
sa_get_element_size(struct sorted_array *sa);

/**
 * Get the number of valid elements that are stored in the sorted
 * array.
 * @param The sorted array.
 * @return The number of valid elements stored in the array.
 */
unsigned int
sa_get_number_of_elements(struct sorted_array *sa);

/**
 * Places a copy of the element at the given address into the
 * array.
 * @param sa The sorted array.
 * @param element The address of the element.
 * @param element_size The size of the item to copy. This does not
 * change the space allocated to the item in the array, but in cases
 * where the element may have a variable size, it prevents copying of
 * bytes which do not belong to the element.
 * @return SA_SUCCESS
 * SA_FAILURE_OOB: If the provided element size was greater than the
 * element size of the sorted array.
 * SA_FAILURE_MALLOC: If memory reallocation was required, and it
 * failed.
 */
sa_result
sa_insert_element(struct sorted_array *sa, element_ptr element,
		size_t element_size);

/**
 * Get the index of an element which is equal to the provided
 * element. IMPORTANT: The index and address of the element may
 * change if elements are added or removed from the array. If you want
 * to do something with the index, do it immediately.
 *
 * This function returns the index of the found element instead of
 * an ELEMENT_PTR because it is easier to convert an index into an
 * ELEMENT_PTR than the reverse. sa_remove_element() requires an
 * index, so this is the best way of finding the element that a user
 * wishes to remove.
 * @param out A pointer to a variable that will contain the index.
 * May be NULL if the index is not required.
 * @param sa The sorted array.
 * @param element The element to lookup.
 * @return A pointer to an equivalent element, or NULL if it does
 * not exist.
 */
sa_result
sa_lookup(element_index* out, struct sorted_array *sa, element_ptr element);

/**
 * Sort elements in the array. This will not repeat the algorithm if
 * the items are already in sorted order.
 * @param sa The sorted array.
 * @return SA_SUCCESS or SA_FAILURE_MALLOC if the memory required
 * to swap items could not be allocated.
 */
sa_result
sa_quicksort(struct sorted_array *sa);

/**
 * Remove the element at the given index.
 * @param sa The sorted array.
 * @param index The index of the element to delete. Must be less than
 * get_number_of_elements().
 */
void
sa_remove_element(struct sorted_array *sa, element_index index);

#endif
