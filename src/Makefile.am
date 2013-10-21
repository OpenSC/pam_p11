MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = test.c

AM_CFLAGS = $(OPENSSL_CFLAGS) $(LIBP11_CFLAGS) $(PAM_CFLAGS)
LIBS = $(OPENSSL_LIBS) $(LIBP11_LIBS) $(PAM_LIBS)
AM_LDFLAGS = -module -shared -avoid-version -shared -no-undefined \
	-export-symbols "$(srcdir)/pam_p11.exports"

pam_LTLIBRARIES = pam_p11_openssh.la  pam_p11_opensc.la 

pam_p11_openssh_la_SOURCES =  pam_p11.c base64.c match_openssh.c \
	pam_p11.exports
pam_p11_opensc_la_SOURCES =  pam_p11.c match_opensc.c \
	pam_p11.exports

format:
	indent -kr -i8 -ts8 -sob -l80 -ss -ncs *.c *.h
