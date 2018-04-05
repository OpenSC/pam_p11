MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = $(OPENSSL_CFLAGS) $(LIBP11_CFLAGS) $(PAM_CFLAGS) -DLOCALEDIR=\"$(localedir)\"
LIBS = $(OPENSSL_LIBS) $(LIBP11_LIBS) $(PAM_LIBS)
AM_LDFLAGS = -module -avoid-version -shared -no-undefined \
	-export-symbols "$(srcdir)/pam_p11.exports"

pam_LTLIBRARIES = pam_p11.la

pam_p11_la_SOURCES = pam_p11.c base64.c \
	match_openssh.c match_opensc.c \
	pam_p11.exports

noinst_PROGRAMS = test_pam_p11

test_pam_p11_SOURCES = test.c $(pam_p11_la_SOURCES)
test_pam_p11_LDADD   = -lpam_misc
test_pam_p11_CFLAGS  = $(AM_CFLAGS) -DLIBDIR=\"$(libdir)\"

format:
	indent -kr -i8 -ts8 -sob -l80 -ss -ncs *.c *.h
