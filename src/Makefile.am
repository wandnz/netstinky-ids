ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = nsids
noinst_LTLIBRARIES =
if ENABLE_MDNS
noinst_LTLIBRARIES += libmdns.la
endif
if ENABLE_UPDATES
noinst_LTLIBRARIES += libupdates.la
endif

# mDNS support
libmdns_la_SOURCES = \
  mdns/ids_mdns_avahi.c \
  mdns/mdns_libuv_integration.c \
  mdns/ids_mdns_avahi.h \
  mdns/mdns_libuv_integration.h
libmdns_la_CFLAGS = $(AVAHI_CFLAGS)
libmdns_la_LIBADD = -luv $(AVAHI_LIBS)

# Online update support (uv_tls via OpenSSL)
libupdates_la_SOURCES = \
  updates/domain_validation.c \
  updates/ids_tls_update.c \
  updates/protocol.c \
  updates/uv_buf_helper.c \
  updates/uv_tls.c \
  updates/domain_validation.h \
  updates/ids_tls_update.h \
  updates/uv_buf_helper.h \
  updates/uv_tls.h
libupdates_la_CFLAGS = @OPENSSL_INCLUDES@
libupdates_la_LDFLAGS = @OPENSSL_LDFLAGS@
libupdates_la_LIBADD = -luv @OPENSSL_LIBS@

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
	ids_event_list.h \
	ids_pcap.h \
	ids_server.h \
	linked_list.h \
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
	utils/file_processing.c \
	dns.c \
	ids_event_list.c \
	ids_pcap.c \
	ids_server.c \
	linked_list.c \
	main.c

nsids_CFLAGS = $(AM_CFLAGS)
nsids_LDADD = -luv -lpcap

if ENABLE_UPDATES
nsids_LDADD += libupdates.la
endif

if ENABLE_MDNS
nsids_LDADD += libmdns.la
endif

bootstrap-clean:
	$(RM) -f Makefile.in aclocal.m4 compile config.* \
             configure depcomp install-sh libtool ltmain.sh \
			 missing mkinstalldirs stamp-h.in
	$(RM) -rf autom4te.cache/

