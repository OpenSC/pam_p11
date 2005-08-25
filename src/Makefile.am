AM_CFLAGS = -Wall -fno-strict-aliasing @OPENSSL_CFLAGS@ @LIBP11_CFLAGS@
AM_LDFLAGS = @OPENSSL_LIBS@ @LIBP11_LIBS@ -module -avoid-version

lib_LTLIBRARIES = pam_p11_openssh.la  pam_p11_opensc.la 

pam_p11_openssh_la_SOURCES =  pam_p11.c base64.c match_openssh.c
pam_p11_openssh_la_LIBADD = @LIBSP11@ 

pam_p11_opensc_la_SOURCES =  pam_p11.c match_opensc.c
pam_p11_opensc_la_LIBADD = @LIBSP11@ 

noinst_PROGRAMS= test

test_SOURCES=test.c
test_LDADD=./.libs/pam_p11_openssh.so

format:
	indent -kr -i8 -ts8 -sob -l80 -ss -ncs *.c *.h

install:       
	$(mkinstalldirs) $(DESTDIR)/$(libdir)/security
	$(libLTLIBRARIES_INSTALL) $(top_builddir)/src/.libs/pam_p11_openssh.so $(DESTDIR)/$(libdir)/security
	$(libLTLIBRARIES_INSTALL) $(top_builddir)/src/.libs/pam_p11_opensc.so $(DESTDIR)/$(libdir)/security

uninstall:       
	$(RM) $(DESTDIR)/$(libdir)/security/pam_p11_openssh.so 
	$(RM) $(DESTDIR)/$(libdir)/security/pam_p11_opensc.so 
	@ rmdir $(DESTDIR)/$(libdir)/security
