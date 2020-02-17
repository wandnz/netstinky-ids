/*
 * portable_endian.h
 *
 *  Created on: Jul 18, 2019
 *      Author: amackint
 *
 * Adapted from Public Domain code `portable_endian.h'
 * written by Mathias Panzenböck to use Autotools
 */
#ifndef PORTABLE_ENDIAN_H__
#define PORTABLE_ENDIAN_H__

#include <config.h>

/* Check include endianness headers discovered by GNU Autotools */
#if (defined(HAVE_ENDIAN_H))
#  include <endian.h>
#elif (defined(HAVE_SYS_ENDIAN_H))
#  include <sys/endian.h>
#elif (defined(HAVE_LIBKERN_OSBYTEORDER_H))
#  include <libkern/OSByteOrder.h>
#endif

/* Apply platform specific actions */
#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)
#  define __WINDOWS__
#endif

#if defined(__linux__) || defined(__CYGWIN__)
#  define __USE_BSD
#elif defined(__APPLE__)
#  define __BYTE_ORDER    BYTE_ORDER
#  define __BIG_ENDIAN    BIG_ENDIAN
#  define __LITTLE_ENDIAN LITTLE_ENDIAN
#  define __PDP_ENDIAN    PDP_ENDIAN
#elif defined(__WINDOWS__)
#  include <winsock2.h>
#  include <sys/param.h>
#  define __BYTE_ORDER    BYTE_ORDER
#  define __BIG_ENDIAN    BIG_ENDIAN
#  define __LITTLE_ENDIAN LITTLE_ENDIAN
#  define __PDP_ENDIAN    PDP_ENDIAN
#endif

#ifndef htobe32
#  if HAVE_DECL_OSSWAPHOSTTOBIGINT32
#    define htobe32(x) OSSwapHostToBigInt32(x)
#  elif ENDIANNESS == LITTLE_ENDIAN
#    define htobe32(x) htonl(x)
#  elif ENDIANNESS == BIG_ENDIAN
#    define htobe32(x) (x)
#  else
#    error byte order not supported
#  endif
#endif

#ifndef be32toh
#  if HAVE_DECL_OSSWAPBIGTOHOSTINT32
#    define be32toh(x) OSSwapBigToHostInt32(x)
#  elif defined(betoh32)
#    define be32toh(x) betoh32(x)
#  elif ENDIANNESS == LITTLE_ENDIAN
#    define be32toh(x) ntohl(x)
#  elif ENDIANNESS == BIG_ENDIAN
#    define be32toh(x) (x)
#  else
#    error byte order not supported
#  endif
#endif

#ifndef htobe64
#  if HAVE_DECL_OSSWAPHOSTTOBIGINT64
#    define htobe64(x) OSSwapHostToBigInt64(x)
#  elif ENDIANNESS == LITTLE_ENDIAN
#    define htobe64(x) htonll(x)
#  elif ENDIANNESS == BIG_ENDIAN
#    define htobe64(x) (x)
#  else
#    error byte order not supported
#  endif
#endif

#ifndef be64toh
#  ifdef HAVE_DECL_OSSWAPBIGTOHOSTINT64
#    define be64toh(x) OSSwapBigToHostInt64(x)
#  elif defined(betoh64)
#    define be64toh(x) betoh64(x)
#  elif ENDIANNESS == LITTLE_ENDIAN
#    define be64toh(x) ntohll(x)
#  elif ENDIANNESS == BIG_ENDIAN
#    define be64toh(x) (x)
#  else
#    error byte order not supported
#  endif
#endif

#endif /* PORTABLE_ENDIAN_H__ */