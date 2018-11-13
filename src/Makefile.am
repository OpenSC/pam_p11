MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = $(OPENSSL_CFLAGS) $(LIBP11_CFLAGS) $(PAM_CFLAGS) -DLOCALEDIR=\"$(localedir)\"
LIBS = $(OPENSSL_LIBS) $(LIBP11_LIBS) $(PAM_LIBS)
AM_LDFLAGS = -module -avoid-version -shared -no-undefined \
	-export-symbols "$(srcdir)/pam_p11.exports"

pam_LTLIBRARIES = pam_p11.la

pam_p11_la_SOURCES = pam_p11.c base64.c \
	match_openssh.c match_opensc.c \
	pam_p11.exports

noinst_PROGRAMS = test-login test-passwd

test_login_SOURCES  = test.c login.c $(pam_p11_la_SOURCES)
test_login_CFLAGS   = $(AM_CFLAGS) -DLIBDIR=\"$(libdir)\" -DTEST

test_passwd_SOURCES = test.c passwd.c $(pam_p11_la_SOURCES)
test_passwd_CFLAGS  = $(AM_CFLAGS) -DLIBDIR=\"$(libdir)\" -DTEST

if HAVE_PAM_MISC
test_login_LDADD    = -lpam_misc
test_passwd_LDADD   = -lpam_misc
endif

format:
	indent -kr -i8 -ts8 -sob -l80 -ss -ncs *.c *.h
