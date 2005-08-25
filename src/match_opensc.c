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

static void add_cert(X509 *cert, X509 ***certs, int *ncerts)
{
	X509 **certs2;
	/* sanity checks */
	if (!cert)
		return;

	if (!certs)
		return;

	if (!ncerts)
		return;

	/* no certs so far */
	if (!*certs) {
		*certs = malloc(sizeof(void *));
		if (!*certs)
			return;
		*certs[0] = cert;
		*ncerts = 1;
		return;
	}

	/* enlarge */

	certs2 = malloc(sizeof(void *) * ((*ncerts) + 1));
	if (!certs2)
		return;

	memcpy(certs2, *certs, sizeof(void *) * (*ncerts));
	certs2[*ncerts] = cert;

	free(*certs);
	*certs = certs2;
	(*ncerts)++;
}

extern int match_user(X509 * x509, const char *login)
{
	char filename[PATH_MAX];
	struct passwd *pw;
	X509 **certs;
	int ncerts, i, rc;
	BIO *in;

	if (!x509)
		return -1;

	if (!login)
		return -1;

	pw = getpwnam(login);
	if (!pw || !pw->pw_dir)
		return -1;

	snprintf(filename, PATH_MAX, "%s/.eid/authorized_certificates", pw->pw_dir);

	in = BIO_new(BIO_s_file());
	if (!in)
		return -1;

        rc = BIO_read_filename(in, filename);
        if (rc != 1) {
                syslog(LOG_ERR,"BIO_read_filename from %s failed\n",filename);
                return -1;
        }

	ncerts=0; certs=NULL;
	for (;;) {
		X509 *cert = PEM_read_bio_X509(in, NULL, 0, NULL);
		if (cert)
			add_cert(cert, &certs, &ncerts);
		else 
			break;
	}

        BIO_free(in);

	for (i = 0; i < ncerts; i++) {
		if (X509_cmp(certs[i],x509) == 0)
			return 1;	/* FOUND */
	}
	return 0;
}
