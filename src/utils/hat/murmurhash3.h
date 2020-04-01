
/* This is MurmurHash3. The original C++ code was placed in the public domain
 * by its author, Austin Appleby. */
#ifndef MURMURHASH3_H
#define MURMURHASH3_H

#include <stdlib.h>

#include "pstdint.h"

uint32_t hash(const char* data, size_t len);

#endif

