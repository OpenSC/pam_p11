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

#define OPENSSH_LINE_MAX 16384	/* from openssh SSH_MAX_PUBKEY_BYTES */

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

static EVP_PKEY *ssh_nistp_line_to_key(char *line)
{
	EVP_PKEY *key;
	EC_KEY *ec_key;
	BIGNUM *x;
	BIGNUM *y;

	unsigned char decoded[OPENSSH_LINE_MAX];
	int len;
	int flen;

	char *b, *c;
	int i;
	int nid;

	/* check allowed key size */
	if (strncmp(line + 16, "256", 3) == 0)
		flen = 32, nid = NID_X9_62_prime256v1;
	else if (strncmp(line + 16, "384", 3) == 0)
		flen = 48, nid = NID_secp384r1;
	else if (strncmp(line + 16, "521", 3) == 0)
		flen = 66, nid = NID_secp521r1;
	else
		return NULL;

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

	/* check key type (must be same in decoded data and at line start) */
	if (strncmp((char *)&decoded[i], line, 19) != 0)
		return NULL;
	i += len;

	/* get integer from blob */
	len =
	    (decoded[i] << 24) + (decoded[i + 1] << 16) +
	    (decoded[i + 2] << 8) + (decoded[i + 3]);
	i += 4;

	/* check curve name - must match key type */
	if(len != 8)
		return NULL;
	if (strncmp((char *)&decoded[i], line + 11, 8) != 0)
		return NULL;
	i += len;

	/* get integer from blob */
	len =
	    (decoded[i] << 24) + (decoded[i + 1] << 16) +
	    (decoded[i + 2] << 8) + (decoded[i + 3]);
	i += 4;

	/* read public key (uncompressed point) */
	/* test if data length is corresponding to key size */
	if (len != 1 + flen * 2)
		return NULL;

	/* check uncompressed indicator */
	if (decoded[i] != 4 )
		return NULL;
	i++;

	/* create key */
	ec_key = EC_KEY_new_by_curve_name(nid);

	/* read point coordinates */
	x = BN_bin2bn(decoded + i, flen, NULL);
	i += flen;
	y = BN_bin2bn(decoded + i, flen, NULL);

	/* do error checking here: valid x, y, ec_key, point on curve.. */
	if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
		EC_KEY_free(ec_key);
		BN_free(x);
		BN_free(y);
		return NULL;
	}

	key = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(key, ec_key);
	return key;
}

extern int match_user_openssh(EVP_PKEY *authkey, const char *login)
{
	char filename[PATH_MAX];
	char line[OPENSSH_LINE_MAX];
	struct passwd *pw;
	int found;
	FILE *file;

	pw = getpwnam(login);
	if (!pw || !pw->pw_dir)
		return -1;

	snprintf(filename, PATH_MAX, "%s/.ssh/authorized_keys", pw->pw_dir);

	file = fopen(filename, "r");
	if (!file)
		return -1;

	found = 0;
	do {
		EVP_PKEY *key = NULL;
		char *cp;
		if (!fgets(line, sizeof line, file))
			break;

		/* Skip leading whitespace, empty and comment lines. */
		for (cp = line; *cp == ' ' || *cp == '\t'; cp++) {
		}
		if (!*cp || *cp == '\n' || *cp == '#') {
			continue;
		}

		if (*cp >= '0' && *cp <= '9') {
			/* ssh v1 key format */
			key = ssh1_line_to_key(cp);
		} else if (strncmp("ssh-rsa", cp, 7) == 0) {
			/* ssh v2 rsa key format */
			key = ssh2_line_to_key(cp);
		} else if (strncmp("ecdsa-sha2-nistp", cp, 16) == 0) {
			/* ssh nistp256/384/521 key */
			key = ssh_nistp_line_to_key(cp);
		}
		if (key == NULL)
			continue;

		if (1 == EVP_PKEY_cmp(authkey, key)) {
			found = 1;
		}
		EVP_PKEY_free(key);
	} while (found == 0);

	fclose(file);

	return found;
}
