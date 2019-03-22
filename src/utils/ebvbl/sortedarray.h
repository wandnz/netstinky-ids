/**
 * A sorted array implementation that can store any type of structure.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "quicksort.h"

const static unsigned int ALLOC_NUM = 10;   // number of extra element spaces
                                            // to add whenever reallocation is
                                            // required

typedef struct SortedArray SortedArray;

typedef int (*cmpElement)(void *a, void *b);
typedef void (*freeElement)(void *a);

typedef int SA_INDEX;   // needs to be signed in case of failure

SortedArray *
sa_initialize(size_t elementSize, cmpElement cmp);

/**
 * Gets the address of the element at the given index in the array. The index
 * can be from 0 to (NUMBER_OF_ELEMENTS - 1).
 * @param sa
 * @param index
 * @return 
 */
void *
sa_get_element(SortedArray *sa, unsigned int index);

SA_INDEX
sa_insert_element(SortedArray *sa, void *element);

void
sa_remove_element(SortedArray *sa, unsigned int index);

bool
sa_contains_element(SortedArray *sa, void *element);

unsigned int
sa_get_number_of_elements(SortedArray *sa);

size_t
sa_get_array_size(SortedArray *sa);

size_t
sa_get_element_size(SortedArray *sa);

bool
sa_is_sorted(SortedArray *sa);

cmpElement
sa_compare(SortedArray *sa);

void *
sa_free(SortedArray *sa, freeElement e_free);

bool
sa_quicksort(SortedArray *sa);