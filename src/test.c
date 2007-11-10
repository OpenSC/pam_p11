#include <stdio.h>
#include <stdlib.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <security/pam_modules.h>

int main(int argc, char **argv)
{
	pam_handle_t *pamh = NULL;

	pam_sm_authenticate(pamh, 0, 1, "/home/aj/opensc/lib/opensc-pkcs11.so");

	exit(0);
}
