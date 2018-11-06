/**
 * Extremely common and very general functions and definitions.
 */

#include <stdio.h>
#include <string.h>
#define DEBUG 1

/*
 * Prints a message if DEBUG is defined. This is not very secure as
 * it allows the user to put in an arbitrary format string.
 */
#define DPRINT(...) do { if (DEBUG) fprintf(stdout, __VA_ARGS__); } while (0)

/*
 * Malloc a structure when the size of the allocation is the same as the size
 * of the structure referenced by PTR.
 */
#define MALLOC(ptr) do { ptr = malloc(sizeof(*ptr)); } while (0)

/*
 * Malloc a structure and zero it when the size of the allocation is the same
 * as the size of the structure referenced by PTR.
 */
#define MALLOC_ZERO(ptr) do { ptr = malloc(sizeof(*ptr)); \
	if (ptr) memset(ptr, 0, sizeof(*ptr)); } while (0)

#define ZERO(ptr) do { memset(ptr, 0, sizeof(*(ptr))); } while (0);

#ifndef MFLETCHE_COMMON_H_
#define MFLETCHE_COMMON_H_

/* -- STRUCTURES -- */

/**
 * It is more efficient on ARM architecture to access arrays by pointer rather
 * than index. This allows a beginning/ending pointer pair to be returned from
 * a function.
 */
struct ptr_range
{
	void *start;
	void *end;
};

#endif /* MFLETCHE_COMMON_H_ */
