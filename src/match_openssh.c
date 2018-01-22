#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

/* how to read the authorized_keys file and the key?
 * see openssh source code auth2-pubkey.c user_key_allowed2
 * and misc.c read_keyfile_line and key.c
 */

#define OPENSSH_LINE_MAX 8192	/* from openssh SSH_MAX_PUBKEY_BYTES */

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
void RSA_get0_key(const RSA *r,
                 const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
	if (n != NULL)
		*n = r->n;
	if (e != NULL)
		*e = r->e;
	if (d != NULL)
		*d = r->d;
}

int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
	/* If the fields n and e in r are NULL, the corresponding input
	* parameters MUST be non-NULL for n and e.  d may be
	* left NULL (in case only the public key is used).
	*/
	if ((r->n == NULL && n == NULL)
	|| (r->e == NULL && e == NULL))
		return 0;

	if (n != NULL) {
		BN_free(r->n);
		r->n = n;
	}
	if (e != NULL) {
		BN_free(r->e);
		r->e = e;
	}
	if (d != NULL) {
		BN_free(r->d);
		r->d = d;
	}

	return 1;
}

#endif

static EVP_PKEY *ssh1_line_to_key(char *line)
{
	EVP_PKEY *key;
	RSA *rsa;
	char *b, *e, *m, *c;
	BIGNUM *rsa_e, *rsa_n;

	key = EVP_PKEY_new();
	if (!key)
		return NULL;

	rsa = RSA_new();

	if (!rsa)
		goto err;

	/* first digitstring: the bits */
	b = line;

	/* second digitstring: the exponent */
	/* skip all digits */
	for (e = b; *e >= '0' && *e <= '0'; e++) ;

	/* must be a whitespace */
	if (*e != ' ' && *e != '\t')
		return NULL;

	/* cut the string in two part */
	*e = 0;
	e++;

	/* skip more whitespace */
	while (*e == ' ' || *e == '\t')
		e++;

	/* third digitstring: the modulus */
	/* skip all digits */
	for (m = e; *m >= '0' && *m <= '0'; m++) ;

	/* must be a whitespace */
	if (*m != ' ' && *m != '\t')
		return NULL;

	/* cut the string in two part */
	*m = 0;
	m++;

	/* skip more whitespace */
	while (*m == ' ' || *m == '\t')
		m++;

	/* look for a comment after the modulus */
	for (c = m; *c >= '0' && *c <= '0'; c++) ;

	/* could be a whitespace or end of line */
	if (*c != ' ' && *c != '\t' && *c != '\n' && *c != '\r' && *c != 0)
		return NULL;

	if (*c == ' ' || *c == '\t') {
		*c = 0;
		c++;

		/* skip more whitespace */
		while (*c == ' ' || *c == '\t')
			c++;

		if (*c && *c != '\r' && *c != '\n') {
			/* we have a comment */
		} else {
			c = NULL;
		}

	} else {
		*c = 0;
		c = NULL;
	}

	/* ok, now we have b e m pointing to pure digit
	 * null terminated strings and maybe c pointing to a comment */

	BN_dec2bn(&rsa_e, e);
	BN_dec2bn(&rsa_n, m);
	if (!RSA_set0_key(rsa, rsa_n, rsa_e, NULL))
		goto err;

	EVP_PKEY_assign_RSA(key, rsa);
	return key;

      err:
	EVP_PKEY_free(key);
	return NULL;
}

extern int sc_base64_decode(const char *in, unsigned char *out, size_t outlen);

static EVP_PKEY *ssh2_line_to_key(char *line)
{
	EVP_PKEY *key;
	RSA *rsa;
	BIGNUM *rsa_e, *rsa_n;
	unsigned char decoded[OPENSSH_LINE_MAX];
	int len;

	char *b, *c;
	int i;

	/* find the mime-blob */
	b = line;

	if (!b)
		return NULL;

	/* find the first whitespace */
	while (*b && *b != ' ')
		b++;

	/* skip that whitespace */
	b++;

	/* find the end of the blob / comment */
	for (c = b; *c && *c != ' ' && 'c' != '\t' && *c != '\r'
	     && *c != '\n'; c++) ;

	*c = 0;

	/* decode binary data */
	if (sc_base64_decode(b, decoded, OPENSSH_LINE_MAX) < 0)
		return NULL;

	i = 0;

	/* get integer from blob */
	len =
	    (decoded[i] << 24) + (decoded[i + 1] << 16) +
	    (decoded[i + 2] << 8) + (decoded[i + 3]);
	i += 4;

	/* now: key_from_blob */
	if (strncmp((char *)&decoded[i], "ssh-rsa", 7) != 0)
		return NULL;

	i += len;

	key = EVP_PKEY_new();
	rsa = RSA_new();

	/* get integer from blob */
	len =
	    (decoded[i] << 24) + (decoded[i + 1] << 16) +
	    (decoded[i + 2] << 8) + (decoded[i + 3]);
	i += 4;

	/* get bignum */
	rsa_e = BN_bin2bn(decoded + i, len, NULL);
	i += len;

	/* get integer from blob */
	len =
	    (decoded[i] << 24) + (decoded[i + 1] << 16) +
	    (decoded[i + 2] << 8) + (decoded[i + 3]);
	i += 4;

	/* get bignum */
	rsa_n = BN_bin2bn(decoded + i, len, NULL);

	/* set e and n */
	if (!RSA_set0_key(rsa, rsa_n, rsa_e, NULL)) {
		EVP_PKEY_free(key);
		RSA_free(rsa);
		return NULL;
	}

	EVP_PKEY_assign_RSA(key, rsa);
	return key;
}

static void add_key(EVP_PKEY * key, EVP_PKEY *** keys, int *nkeys)
{
	EVP_PKEY **keys2;
	/* sanity checks */
	if (!key)
		return;

	if (!keys)
		return;

	if (!nkeys)
		return;

	/* no keys so far */
	if (!*keys) {
		*keys = malloc(sizeof(void *));
		if (!*keys)
			return;
		*keys[0] = key;
		*nkeys = 1;
		return;
	}

	/* enlarge */

	keys2 = malloc(sizeof(void *) * ((*nkeys) + 1));
	if (!keys2)
		return;

	memcpy(keys2, *keys, sizeof(void *) * (*nkeys));
	keys2[*nkeys] = key;

	free(*keys);
	*keys = keys2;
	(*nkeys)++;
}

extern int match_user(X509 * x509, const char *login)
{
	char filename[PATH_MAX];
	char line[OPENSSH_LINE_MAX];
	struct passwd *pw;
	FILE *file;
	EVP_PKEY **keys = NULL;
	EVP_PKEY *authkey;
	const BIGNUM *rsa_e, *rsa_n, *auth_e, *auth_n;
	int nkeys = 0, i;

	authkey = X509_get_pubkey(x509);
	if (!authkey)
		return 0;

	pw = getpwnam(login);
	if (!pw || !pw->pw_dir)
		return -1;

	snprintf(filename, PATH_MAX, "%s/.ssh/authorized_keys", pw->pw_dir);

	file = fopen(filename, "r");
	if (!file)
		return -1;

	for (;;) {
		char *cp;
		if (!fgets(line, OPENSSH_LINE_MAX, file))
			break;

		/* Skip leading whitespace, empty and comment lines. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++)

			if (!*cp || *cp == '\n' || *cp == '#')
				continue;

		if (*cp >= '0' && *cp <= '9') {
			/* ssh v1 key format */
			EVP_PKEY *key = ssh1_line_to_key(cp);
			if (key)
				add_key(key, &keys, &nkeys);

		}
		if (strncmp("ssh-rsa", cp, 7) == 0) {
			/* ssh v2 rsa key format */
			EVP_PKEY *key = ssh2_line_to_key(cp);
			if (key)
				add_key(key, &keys, &nkeys);
		}
	}

	fclose(file);

	for (i = 0; i < nkeys; i++) {
		RSA *authrsa, *rsa;

		authrsa = EVP_PKEY_get1_RSA(authkey);
		if (!authrsa)
			continue;	/* not RSA */

		rsa = EVP_PKEY_get1_RSA(keys[i]);
		if (!rsa)
			continue;	/* not RSA */

		RSA_get0_key(rsa, &rsa_n, &rsa_e, NULL);
		RSA_get0_key(authrsa, &auth_n, &auth_e, NULL);

		if (BN_cmp(rsa_e, auth_e) != 0)
			continue;
		if (BN_cmp(rsa_n, auth_n) != 0)
			continue;
		return 1;	/* FOUND */
	}
	return 0;
}
