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

struct ebvbl;

typedef enum
{
	EBVBL_SUCCESS,
	EBVBL_FAILURE,
	EBVBL_FAILURE_MALLOC	/* Could not allocate enough memory. */
} ebvbl_result;

/* Type used for the bit field factor. When inserting or searching
 * for an element in the EBVBL, the f-bit prefix of the element is
 * examined. Each bit in the bit vector contains information about
 * whether there are elements in the list with a particular f-bit
 * prefix. The bit field factor is set on creation of the EBVBL and
 * determines how many bits are in that prefix. It affects the memory
 * required for the bit vector.
 */
typedef unsigned int ebvbl_bff;

typedef void* element_ptr;

/* A prefix of length determined by ebvbl_bff. */
typedef unsigned int element_prefix;

/*
 * A function which must be implemented by the user of the EBVBL,
 * which extracts the first n bits from an element.
 */
typedef element_prefix (*element_fb)(element_ptr item, ebvbl_bff bff);

/**
 * Returns true if an element equivalent to the provided ELEMENT is in the
 * data structure.
 * @param e
 * @param element
 * @return True if the data structure contains an equivalent element
 */
bool
ebvbl_contains_element(struct ebvbl *e, element_ptr element);

/**
 * Creates an empty array and bit vector structure.
 * @param elementSize   Size of each element in bytes.
 *                      Must not be 0.
 * @param cmp   Comparison function for element types.
 *              Must not be NULL.
 * @param bf The bit factor (or how many bits to use to index the bit vector).
 * 				Must be greater than zero.
 * @param fb    Function which extracts the first bits from an item.
 * 				Must not be NULL.
 * @param element_realloc	Number of elements to allocate space for
 * 							when a reallocation must be performed.
 * 							Must be greater than 0.
 * @return A pointer to an initialized EBVBL structure (or NULL if failed)
 */
struct ebvbl *
ebvbl_create(size_t element_size, element_cmp cmp, ebvbl_bff bff, element_fb fb,
		unsigned int element_realloc);

/**
 * Frees an EBVBL and all substructures. Takes a function pointer argument which
 * can be used to clean up each element (but can also be NULL if this is not
 * required).
 * @param e         The address of a pointer to an EBVBL structure.
 * 					The pointer will be set to NULL.
 * @param e_free    A function that cleans up each element (can be NULL).
 */
void
ebvbl_free(struct ebvbl **e, element_free e_free);

/**
 * Get the bit field factor (f) for an initialized EBVBL structure. The bit
 * field factor is the number of bits of the IP address that will be extracted
 * and used to index the bit vector.
 * @param ebvbl An initialized EBVBL structure.
 * @return The bit field factor.
 */
ebvbl_bff
ebvbl_get_bit_field_factor(struct ebvbl *ebvbl);

/**
 * Get the bit vector radius for an initialized EBVBL structure. The bit vector
 * radius is the number of IP addresses which each bit in the bit vector will
 * cover (i.e. IP addresses with the same f-bit prefix).
 * @param ebvbl
 * @return 
 */
unsigned int
ebvbl_get_bit_vector_radius(ebvbl_bff bff);

/**
 * Get the address of an element in the array with the given index.
 * @param e
 * @param index Must be greater than or equal to zero and less than the number
 *              of elements in the array.
 * @return The address of the element
 */
element_ptr
ebvbl_get_element(struct ebvbl *e, unsigned int index);

/**
 * Gets the number of elements that are stored in the structure.
 * @param e An initialized EBVBL structure.
 * @return The number of elements stored in the structure.
 */
unsigned int
ebvbl_get_number_of_elements(struct ebvbl *e);

/**
 * Attempt to insert an element into the EBVBL structure.
 * @param e The EBVBL.
 * @param element The element to insert.
 * @param element_size The amount of bytes to copy into the array.
 * @return EBVBL_SUCCESS or EBVBL_FAILURE_MALLOC.
 */
ebvbl_result
ebvbl_insert_element(struct ebvbl *e, element_ptr element, size_t element_size);

/**
 * Remove the element at the given index.
 * @param e The EBVBL.
 * @param index The index of the element to remove. Must be less than
 * ebvbl_get_number_of_elements().
 */
void
ebvbl_remove_element(struct ebvbl *e, element_index index);
