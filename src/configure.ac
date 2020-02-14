#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script

AC_PREREQ(2.69)
AC_INIT([nsids], [0.1], [amackint@waikato.ac.nz])
AC_USE_SYSTEM_EXTENSIONS
AM_INIT_AUTOMAKE([1.11 -Wall -Werror foreign subdir-objects])

AM_PROG_AR
LT_PREREQ([2.4])
LT_INIT([dlopen])

AC_LANG([C])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])
AC_C_BIGENDIAN([
  AC_DEFINE([ENDIANNESS], [BIG_ENDIAN], [Define to either BIG_ENDIAN or LITTLE_ENDIAN])
], [
  AC_DEFINE([ENDIANNESS], [LITTLE_ENDIAN], [Define to either BIG_ENDIAN or LITTLE_ENDIAN])
], [
  AC_DEFINE([ENDIANNESS], [BIG_ENDIAN], [Define to either BIG_ENDIAN or LITTLE_ENDIAN])
  AC_MSG_WARN(["Universal" endianness detected, defaulting to BIG_ENDIAN])
])

# Checks for library functions.
AC_HEADER_ASSERT
AC_HEADER_STDC
AC_HEADER_STDBOOL
AC_HEADER_TIME
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_STRNLEN

# Checks for header files.
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([errno.h])
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([math.h])
AC_CHECK_HEADERS([net/ethernet.h])
AC_CHECK_HEADERS([netinet/in.h], [], [],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
# endif
])
AC_CHECK_HEADERS([netinet/ip.h], [], [],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
# endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
# endif
])
AC_CHECK_HEADERS([netinet/udp.h])
AC_CHECK_HEADERS([poll.h])
AC_CHECK_HEADERS([signal.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([stdio.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([strings.h])
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([wchar.h])
AC_CHECK_HEADERS([endian.h sys/endian.h], [break])

AC_CHECK_HEADER([uv.h], [], [
  AC_MSG_ERROR([required header uv.h not found])
])
AC_SEARCH_LIBS([uv_default_loop], [uv], [], [
  AC_MSG_ERROR([required library libuv not found])
])

AC_CHECK_HEADER([pcap/pcap.h], [], [
  AC_MSG_ERROR([required header pcap/pcap.h not found])
])
AC_SEARCH_LIBS([pcap_create], [pcap], [], [
  AC_MSG_ERROR([required library libpcap not found])
])

# Check for byte-ordering macro definitions on Apple systems
AC_CHECK_DECLS([
  OSSwapHostToBigInt32,
  OSSwapBigToHostInt32,
  OSSwapHostToBigInt64,
  OSSwapBigToHostInt64], [], [], [[#include <libkern/OSByteOrder.h>]])

AC_CHECK_FUNCS([clock_gettime])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([memcpy])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strtoul])

# Define ./configure options
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug],
    [build with debugging symbols])],
  [debug="$enableval"], [debug=no])

AC_ARG_ENABLE([mdns],
  [AS_HELP_STRING([--enable-mdns],
    [enable mDNS advertisement with avahi])],
  [mdns="$enableval"], [mdns=yes])

AC_ARG_ENABLE([updates],
  [AS_HELP_STRING([--enable-updates],
    [enable online updates over tls])],
  [updates="$enableval"], [updates=yes])

# Act on enable-debug option
AS_IF([test "x$debug" != xno],
  [AC_DEFINE(DEBUG, [1], [Define to enable DEBUG features])])

# Act on enable-mdns option
AS_IF([test "x$mdns" != xno],
  [
    PKG_CHECK_MODULES([AVAHI], [avahi-client])
    AM_CONDITIONAL(ENABLE_MDNS, true)
  ], [
    AM_CONDITIONAL(ENABLE_MDNS, false)
    AC_DEFINE(NO_MDNS, [1], [Define to disable mDNS listener])
  ])

# Act on enable-updates option
AS_IF([test "x$updates" != xno],
  [
    AX_CHECK_OPENSSL(
      [AC_DEFINE([HAVE_OPENSSL], [1], [Define to 1 if you have OpenSSL])]
      [have_openssl=yes])
    AM_CONDITIONAL(ENABLE_UPDATES, true)
  ], [
    AM_CONDITIONAL(ENABLE_UPDATES, false)
    AC_DEFINE(NO_UPDATES, [1], [Define to disable online updates])
  ])

if test "x$debug" != xno && test "x$have_openssl" = xyes; then
   AC_MSG_CHECKING([for SSL_CTX_set_keylog_callback])
   save_LDFLAGS="$LDFLAGS"
   save_LIBS="$LIBS"
   LDFLAGS="$LDFLAGS $OPENSSL_LDFLAGS"
   LIBS="$LIBS $OPENSSL_LIBS"
   AC_LINK_IFELSE([
     AC_LANG_PROGRAM([
       [#include <openssl/ssl.h>]],
       [
[const SSL_METHOD *method = SSLv23_method();]
[SSL_CTX *ctx = SSL_CTX_new(method);]
[SSL_CTX_set_keylog_callback(ctx, (SSL_CTX_keylog_cb_func) 0);]
     ])
   ],
   [
    AC_MSG_RESULT([yes])
    AC_DEFINE_UNQUOTED([HAVE_SSL_CTX_SET_KEYLOG_CALLBACK], 1,
        [Define to 1 if you have the SSL_CTX_set_keylog_callback function])
   ],
   [
    AC_MSG_RESULT([no])
   ])
   LDFLAGS="$save_LDFLAGS"
   LIBS="$save_LIBS"
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
