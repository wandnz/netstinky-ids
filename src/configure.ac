AC_INIT([nsids], [0.1], [amackint@waikato.ac.nz])

AM_INIT_AUTOMAKE
AC_PROG_CC
LT_INIT
AC_CONFIG_MACRO_DIRS([m4])

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

# Define ./configure options
AC_ARG_ENABLE([debug],
  [AS_HELP_STRING([--enable-debug], [build with debugging symbols])])

AC_ARG_ENABLE([mdns],
  [AS_HELP_STRING([--enable-mdns], [enable mDNS advertisement with avahi])],
  [],
  [enable_mdns=yes])

AC_ARG_ENABLE([updates],
  [AS_HELP_STRING([--enable-updates], [enable online updates over tls])],
  [],
  [enable_updates=yes])

# Act on enable-debug option
AS_IF([test "x$enable_debug" != xno],
  [
  AM_CONDITIONAL(ENABLE_DEBUG, true)
  AC_DEFINE(DEBUG,[],[])
  ], [
  AM_CONDITIONAL(ENABLE_DEBUG, false)
  ]
)

# Act on enable-mdns option
AS_IF([test "x$enable_mdns" != xno],
  [
  PKG_CHECK_MODULES([AVAHI], [avahi-client])
  AM_CONDITIONAL(ENABLE_MDNS, true)
  ], [
  AM_CONDITIONAL(ENABLE_MDNS, false)
  AC_DEFINE(NO_MDNS,[],[])
  ]
)

# Act on enable-updates option
AS_IF([test "x$enable_updates" != xno],
  [
  PKG_CHECK_MODULES([UPDATES], [libcurl >= 4 libssl libcrypto])
  AM_CONDITIONAL(ENABLE_UPDATES, true)
  ], [
  AM_CONDITIONAL(ENABLE_UPDATES, false)
  AC_DEFINE(NO_UPDATES,[],[])
  ]
)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
