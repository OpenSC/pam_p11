#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>

#ifndef LIBDIR
#define LIBDIR "/usr/lib"
#endif

int main(int argc, const char **argv)
{
	char user[32];
	char module[4096];
	const char *pam_argv[] = {
		module,
	};
	pam_handle_t *pamh = NULL;
	struct pam_conv conv = {
		misc_conv,
		NULL,
	};
	int r;
	int status = EXIT_FAILURE;

	/* initialize default values */
	strcpy(module, LIBDIR "/opensc-pkcs11.so");
	if (0 != getlogin_r(user, sizeof user))
		goto err;

	switch (argc) {
		case 3:
			strncpy(user, argv[2], sizeof user);
			/* fall through */
		case 2:
			strncpy(module, argv[1], sizeof module);
			/* fall through */
		case 1:
			break;

		default:
			puts("Usage: test [pkcs11_module.so [username]]");
			goto err;
	}
	printf("Authenticating '%s' with '%s'\n", user, module);

	r = pam_start("", user, &conv, &pamh);
	if (PAM_SUCCESS != r)
		goto pam_err;

	r = pam_sm_authenticate(pamh, 0, sizeof pam_argv/sizeof *pam_argv, pam_argv);
	if (PAM_SUCCESS != r)
		goto pam_err;

	status = EXIT_SUCCESS;

pam_err:
	if (PAM_SUCCESS != r) {
		printf("Error: %s\n", pam_strerror(pamh, r));
	} else {
		printf("OK\n");
	}
	pam_end(pamh, r);

err:
	exit(status);
}
