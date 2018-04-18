/*
 * Copyright (C) 2018 Frank Morgner <frankmorgner@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

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

extern int pam_sm_test(pam_handle_t *pamh, int flags, int argc, const char **argv);

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
			printf("Usage: %s [pkcs11_module.so [username]]\n", argv[0]);
			/* fall through */
		case 0:
			goto err;
	}
	module[(sizeof module) - 1] = '\0';
	user[(sizeof user) - 1] = '\0';
	printf("Using '%s' for '%s'\n", module, user);

	r = pam_start("", user, &conv, &pamh);
	if (PAM_SUCCESS != r)
		goto pam_err;

	r = pam_sm_test(pamh, 0, sizeof pam_argv/sizeof *pam_argv, pam_argv);
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
