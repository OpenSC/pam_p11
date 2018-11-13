AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [2])
define([PACKAGE_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [_git])
define([PRODUCT_BUGREPORT], [https://github.com/OpenSC/pam_p11/issues])

AC_INIT([pam_p11],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX],[PRODUCT_BUGREPORT])
AC_CONFIG_AUX_DIR([.])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([src/pam_p11.c])

AC_CANONICAL_HOST
AC_PROG_CC
PKG_PROG_PKG_CONFIG
AC_C_BIGENDIAN

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--disable-strict],[disable strict compile mode @<:@enabled@:>@])],
	,
	[enable_strict="yes"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@disabled@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_WITH(
	[pamdir],
	[AS_HELP_STRING([--with-pamdir=PATH],[Specify the directory where PAM modules are stored])],
	[pamdir="${withval}"],
	[
		if test "${prefix}" = "/usr"; then
			pamdir="/lib${libdir##*/lib}/security"
		else
			pamdir="\$(libdir)/security"
		fi
	]
)

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION(0.18.3)

dnl Add the languages which your application supports here.
ALL_LINGUAS="de"

dnl Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_MAKE_SET

dnl Add libtool support.
ifdef(
	[LT_INIT],
	[LT_INIT],
	[AC_PROG_LIBTOOL]
)

PKG_CHECK_MODULES([LIBP11], [libp11 >= 0.2.4],, [AC_MSG_ERROR([libp11 is required])])
PKG_CHECK_MODULES(
	[OPENSSL],
	[libcrypto >= 0.9.7],
	,
	[PKG_CHECK_MODULES(
		[OPENSSL],
		[openssl >= 0.9.7],
		,
		[AC_CHECK_LIB(
			[crypto],
			[RSA_version],
			[OPENSSL_LIBS="-lcrypto"],
			[AC_MSG_ERROR([Cannot find OpenSSL])]
		)]
	)]
)

saved_LIBS="$LIBS"
LIBS="$OPENSSL_LIBS $LIBS"
AC_CHECK_FUNCS(EVP_MD_CTX_new EVP_MD_CTX_free EVP_MD_CTX_reset)
LIBS="$saved_LIBS"

if test -z "${PAM_LIBS}"; then
	AC_ARG_VAR([PAM_CFLAGS], [C compiler flags for pam])
	AC_ARG_VAR([PAM_LIBS], [linker flags for pam])
	AC_CHECK_LIB(
		[pam],
		[pam_authenticate],
		[PAM_LIBS="-lpam"],
		[AC_MSG_ERROR([Cannot find pam])]
	)
fi

saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS} ${LIBP11_CFLAGS} ${PAM_CFLAGS}"
LIBS="$LIBS ${OPENSSL_LIBS} ${LIBP11_LIBS} ${PAM_LIBS}"

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([ \
	string.h syslog.h fcntl.h unistd.h security/pam_ext.h security/pam_misc.h \
])
AC_TYPE_SIZE_T
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([memset strdup strerror PKCS11_enumerate_public_keys PKCS11_is_logged_in pam_vprompt openpam_ttyconv])

AC_CHECK_LIB([pam_misc], [misc_conv])
AM_CONDITIONAL([HAVE_PAM_MISC], [test "$ac_cv_lib_pam_misc_misc_conv" = yes])

CFLAGS="${saved_CFLAGS}"
LIBS="$saved_LIBS"

AC_SUBST([pamdir])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra -Wno-unused-parameter -Werror"
fi

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	po/Makefile.in
])
AC_OUTPUT

cat <<EOF

pam_p11 has been configured with the following options:


Version:                 ${PACKAGE_VERSION}
Libraries:               $(eval eval eval echo "${libdir}")

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

pamdir                   ${pamdir}

PAM_CFLAGS:              ${PAM_CFLAGS}
PAM_LIBS:                ${PAM_LIBS}
LIBP11_CFLAGS:           ${LIBP11_CFLAGS}
LIBP11_LIBS:             ${LIBP11_LIBS}
OPENSSL_CFLAGS:          ${OPENSSL_CFLAGS}
OPENSSL_LIBS:            ${OPENSSL_LIBS}

EOF
