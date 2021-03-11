ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = nsids
noinst_LTLIBRARIES =
if ENABLE_MDNS
noinst_LTLIBRARIES += libmdns.la
endif
if ENABLE_UPDATES
noinst_LTLIBRARIES += libuvtls.la \
	libupdates.la
endif

# mDNS support
libmdns_la_SOURCES = \
	mdns/ids_mdns_avahi.c \
	mdns/uv-watch.c \
	mdns/ids_mdns_avahi.h \
	mdns/uv-watch.h
libmdns_la_CFLAGS = $(AVAHI_CFLAGS)
libmdns_la_LIBADD = -luv $(AVAHI_LIBS)

# libuv TLS handle type
libuvtls_la_SOURCES = \
	utils/uvtls/backends/openssl.c \
	utils/uvtls/backends/openssl.h \
	utils/uvtls/uv_tls.c \
	utils/uvtls/uv_tls.h
libuvtls_la_CFLAGS = @OPENSSL_INCLUDES@
libuvtls_la_LDFLAGS = @OPENSSL_LDFLAGS@
libuvtls_la_LIBADD = -luv @OPENSSL_LIBS@

# Online update support (uv_tls via OpenSSL)
libupdates_la_SOURCES = \
	updates/domain_validation.c \
	updates/ids_tls_update.c \
	updates/protocol.c \
	updates/uv_buf_helper.c \
	updates/domain_validation.h \
	updates/ids_tls_update.h \
	updates/uv_buf_helper.h
libupdates_la_CFLAGS = @OPENSSL_INCLUDES@
libupdates_la_LDFLAGS = @OPENSSL_LDFLAGS@
libupdates_la_LIBADD = -luv @OPENSSL_LIBS@ libuvtls.la

nsids_SOURCES = \
	common.h \
	dns.h \
	blacklist/domain_blacklist.h \
	blacklist/feodo_ip_blacklist.h \
	blacklist/ids_blacklist.h \
	blacklist/ip_blacklist.h \
	blacklist/ids_storedvalues.h \
	blacklist/urlhaus_domain_blacklist.h \
	error/ids_error.h \
	utils/byte_array.h \
	utils/common.h \
	utils/str.h \
	utils/ebvbl/ebvbl.h \
	utils/ebvbl/quicksort.h \
	utils/ebvbl/sortedarray.h \
	utils/hat/ahtable.h \
	utils/hat/common.h \
	utils/hat/hat-trie.h \
	utils/hat/misc.h \
	utils/hat/murmurhash3.h \
	utils/hat/portable_endian.h \
	utils/hat/pstdint.h \
	utils/file_processing.h \
	utils/logging.h \
	utils/logging.c \
	ids_event_list.h \
	ids_pcap.h \
	ids_server.h \
	privileges.h \
	blacklist/domain_blacklist.c \
	blacklist/feodo_ip_blacklist.c \
	blacklist/ids_blacklist.c \
	blacklist/ip_blacklist.c \
	blacklist/ids_storedvalues.c \
	blacklist/urlhaus_domain_blacklist.c \
	error/ids_error.c \
	utils/byte_array.c \
	utils/str.c \
	utils/ebvbl/ebvbl.c \
	utils/ebvbl/quicksort.c \
	utils/ebvbl/sortedarray.c \
	utils/hat/ahtable.c \
	utils/hat/hat-trie.c \
	utils/hat/misc.c \
	utils/hat/murmurhash3.c \
	utils/linked_list.c \
	utils/linked_list.h \
	utils/file_processing.c \
	dns.c \
	ids_event_list.c \
	ids_pcap.c \
	ids_server.c \
	main.c \
	privileges.c

nsids_CFLAGS = $(AM_CFLAGS)
nsids_LDADD = -luv -lpcap

if ENABLE_UPDATES
nsids_LDADD += libuvtls.la \
	libupdates.la
endif

if ENABLE_MDNS
nsids_LDADD += libmdns.la
endif

bootstrap-clean:
	$(RM) -f Makefile.in aclocal.m4 compile config.* \
			 configure depcomp install-sh libtool ltmain.sh \
			 missing mkinstalldirs stamp-h.in
	$(RM) -rf autom4te.cache/
