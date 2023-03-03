#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

extern int match_user_opensc(EVP_PKEY *authkey, const char *login)
{
	char filename[PATH_MAX];
	struct passwd *pw;
	int found;
	BIO *in;
	X509 *cert = NULL;

	if (NULL == authkey || NULL == login)
		return -1;

	pw = getpwnam(login);
	if (!pw || !pw->pw_dir)
		return -1;

	snprintf(filename, PATH_MAX, "%s/.eid/authorized_certificates",
		 pw->pw_dir);

	in = BIO_new(BIO_s_file());
	if (!in)
		return -1;

	if (BIO_read_filename(in, filename) != 1) {
		syslog(LOG_ERR, "BIO_read_filename from %s failed\n", filename);
		return -1;
	}

	found = 0;
	do {
		EVP_PKEY *key;
		if (NULL == PEM_read_bio_X509(in, &cert, 0, NULL)) {
			break;
		}
		key = X509_get_pubkey(cert);
		if (key == NULL)
			continue;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (1 == EVP_PKEY_cmp(authkey, key)) {
			found = 1;
		}
#else
		if (1 == EVP_PKEY_eq(authkey, key)) {
			found = 1;
		}
#endif
		EVP_PKEY_free(key);
	} while (found == 0);

	if (cert) {
		X509_free(cert);
	}

	BIO_free(in);

	return found;
}
