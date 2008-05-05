# $Id$

# Require autoconf 2.52
AC_PREREQ(2.52)

# Process this file with autoconf to produce a configure script.
AC_INIT(pam_p11,[0.1.3-svn])
AC_CONFIG_SRCDIR([src/pam_p11.c])
AC_CANONICAL_TARGET([])
AM_INIT_AUTOMAKE

AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h syslog.h fcntl.h unistd.h security/pam_ext.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset strdup strerror])

# Checks for libraries.
AC_CHECK_LIB(pam, pam_get_item, , AC_MSG_ERROR(could not locate pam libraries))

# Check and set OpenSSL paths
PKG_CHECK_MODULES(OPENSSL, openssl, [], [ AC_MSG_ERROR(openssl not found) ])
PKG_CHECK_MODULES(LIBP11, libp11, [], [ AC_MSG_ERROR(libp11 not found) ])

AC_CONFIG_FILES([ 
Makefile
aclocal/Makefile
doc/Makefile
src/Makefile
])
AC_OUTPUT
