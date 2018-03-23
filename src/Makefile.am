MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = $(OPENSSL_CFLAGS) $(LIBP11_CFLAGS) $(PAM_CFLAGS)
LIBS = $(OPENSSL_LIBS) $(LIBP11_LIBS) $(PAM_LIBS)
AM_LDFLAGS = -module -avoid-version -shared -no-undefined \
	-export-symbols "$(srcdir)/pam_p11.exports"

pam_LTLIBRARIES = pam_p11_openssh.la  pam_p11_opensc.la

pam_p11_openssh_la_SOURCES = pam_p11.c base64.c match_openssh.c \
	pam_p11.exports

pam_p11_opensc_la_SOURCES  = pam_p11.c match_opensc.c \
	pam_p11.exports

noinst_PROGRAMS = test_pam_p11_openssh test_pam_p11_opensc

test_pam_p11_openssh_SOURCES = test.c $(pam_p11_openssh_la_SOURCES)
test_pam_p11_openssh_LDADD   = -lpam_misc
test_pam_p11_openssh_CFLAGS  = $(AM_CFLAGS) -DLIBDIR=\"$(libdir)\"

test_pam_p11_opensc_SOURCES  = test.c $(pam_p11_opensc_la_SOURCES)
test_pam_p11_opensc_LDADD    = -lpam_misc
test_pam_p11_opensc_CFLAGS   = $(AM_CFLAGS) -DLIBDIR=\"$(libdir)\"

format:
	indent -kr -i8 -ts8 -sob -l80 -ss -ncs *.c *.h
