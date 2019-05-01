/*
 * A C implementation of The Enhanced Bit Vector Based Blacklisting Algorithm
 * (EBVBL), based on 'Bit vector algorithms enabling high-speed and
 * memory-efficient firewall blacklisting' by Thames, Abler and Keeling (2009).
 * 
 * The EBVBL is designed for IPv4 address blacklisting.
 * 
 * The worst-case performance when searching a sorted array occurs when the item
 * that is being searched for is not in the array. The EBVBL uses a sorted array
 * and an additional bit vector to reduce the chance that the worst-case leads
 * to a search of the array.
 * 
 * The first f bits of each IP address are used to index a bit in the bit
 * vector -- the bit vector must be 2^f bits in length. If the bit is 0, there
 * are no IP addresses in the sorted array with that prefix and the search can
 * end early, without searching the sorted array.
 */
#include <stdint.h>
#include <math.h>
#include "sortedarray.h"

typedef struct EBVBL EBVBL;

// Function which extracts the first bits from an item.
typedef unsigned int (*first_bits)(void *item, unsigned int num_bits);

static const unsigned int maxKeyLength = 32;    // in bits

/**
 * Get the bit field factor (f) for an initialized EBVBL structure. The bit
 * field factor is the number of bits of the IP address that will be extracted
 * and used to index the bit vector.
 * @param ebvbl An initialized EBVBL structure.
 * @return The bit field factor.
 */
unsigned int
ebvbl_get_bit_field_factor(EBVBL *ebvbl);

/**
 * Get the bit vector radius for an initialized EBVBL structure. The bit vector
 * radius is the number of IP addresses which each bit in the bit vector will
 * cover (i.e. IP addresses with the same f-bit prefix).
 * @param f
 * @return 
 */
unsigned int
ebvbl_get_bit_vector_radius(unsigned int f);

/**
 * Gets the size of the bit vector (in bits).
 * @param f
 * @return 
 */
unsigned int
ebvbl_get_bit_vector_size(unsigned int f);

/**
 * Creates an empty array and bit vector structure.
 * @param elementSize   Size of each element in bytes.
 *                      Must not be 0.
 * @param cmp   Comparison function for element types.
 *              Must not be NULL.
 * @param f The bit factor (or how many bits to use to index the bit vector)
 *          Value should be between 1 and MAXKEYLENGTH inclusive
 * @param fb    Function which extracts the first bits from an item.
 * @return A pointer to an initialized EBVBL structure (or NULL if failed)
 */
EBVBL *
ebvbl_init(size_t elementSize, cmpElement cmp, unsigned int f, first_bits fb);



/**
 * Get the address of an element in the array with the given index.
 * @param e
 * @param index Must be greater than or equal to zero and less than the number
 *              of elements in the array.
 * @return The address of the element
 */
void *
ebvbl_get_element(EBVBL *e, unsigned int index);

/**
 * Gets the number of elements that are stored in the structure.
 * @param e An initialized EBVBL structure.
 * @return The number of elements stored in the structure.
 */
unsigned int
ebvbl_get_number_of_elements(EBVBL *e);

/**
 * Gets the index of the bit in the bit vector that indicates whether any
 * elements in the array share a prefix with ELEMENT.
 * @param e
 * @param element
 * @return 
 */
unsigned int
ebvbl_get_bv_index(EBVBL *e, void *element);

/**
 * Returns true if an element equivalent to the provided ELEMENT is in the
 * data structure.
 * @param e
 * @param element
 * @return True if the data structure contains an equivalent element
 */
bool
ebvbl_contains(EBVBL *e, void *element);

void
ebvbl_clear(EBVBL *e, freeElement free_item);

/**
 * Frees an EBVBL and all substructures. Takes a function pointer argument which
 * can be used to clean up each element (but can also be NULL if this is not
 * required).
 * @param e         The address of an EBVBL structure.
 * @param e_free    A function that cleans up each element (can be NULL).
 * @return          NULL
 */
EBVBL *
ebvbl_free(EBVBL *e, freeElement e_free);

SA_INDEX
ebvbl_insert_element(EBVBL *e, void *element);

/**
 * Removes the element at the given index.
 * @param e	The address of an EBVBL structure.
 * @param index	The index of the element to remove.
 */
void
ebvbl_remove_element(EBVBL *e, unsigned int index);

/**
 * Sort the SortedArray structure within the EBVBL. Will not sort if it is
 * already in sorted order.
 * @param e
 * @return True if the sort was successful.
 */
bool
ebvbl_sort(EBVBL *e);

/**
 * Print the contents of the EBVBL to the console.
 * @param e
 */
void
ebvbl_print(EBVBL *e);
