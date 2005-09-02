SUBDIRS = . aclocal doc src

EXTRA_DIST = COPYING bootstrap

AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES = \
	Makefile.in config.h.in configure \
	install-sh ltmain.sh missing mkinstalldirs \
	compile depcomp config.log config.status \
	config.guess config.sub acinclude.m4 aclocal.m4

dist: gendoc

gendoc:
	sh $(srcdir)/doc/export-wiki.sh $(srcdir)/doc
