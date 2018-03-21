/*
 * libp11 PAM Login Module
 * Copyright (C) 2003 Mario Strasser <mast@gmx.net>,
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
 */

#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <libp11.h>

/* We have to make this definitions before we include the pam header files! */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#else
#define pam_syslog(handle, level, msg...) syslog(level, ## msg)
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

#define LOGNAME   "pam_p11"	/* name for log-file entries */

#define RANDOM_SOURCE "/dev/urandom"
#define RANDOM_SIZE 127
#define MAX_SIGSIZE 256

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey) {
	if (pkey->type != EVP_PKEY_RSA) {
		return NULL;
	}
	return pkey->pkey.rsa;
}
#endif

extern int match_user(X509 * x509, const char *login);

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
				   const char **argv)
{
	int rv;
	const char *user;
	char *password;

	struct pam_conv *conv;
	struct pam_response *resp;
	struct pam_message *(msgp[1]);

	PKCS11_CTX *ctx;
	PKCS11_SLOT *slot, *slots;
	PKCS11_CERT *certs;
	unsigned int nslots, ncerts;
	PKCS11_KEY *authkey;
	PKCS11_CERT *authcert;

	EVP_PKEY *pubkey = NULL;
	RSA *rsa;

	unsigned char rand_bytes[RANDOM_SIZE];
	unsigned char signature[MAX_SIGSIZE];
	int fd;
	unsigned siglen;
	unsigned int i;

	/* check parameters */
	if (argc != 1) {
		pam_syslog(pamh, LOG_ERR, "need pkcs11 module as argument");
		return PAM_ABORT;
	}

	/* init openssl */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	ctx = PKCS11_CTX_new();

	/* get user name */
	rv = pam_get_user(pamh, &user, NULL);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user() failed %s",
		       pam_strerror(pamh, rv));
		return PAM_USER_UNKNOWN;
	}

	/* load pkcs #11 module */
	rv = PKCS11_CTX_load(ctx, argv[0]);
	if (rv) {
		pam_syslog(pamh, LOG_ERR, "loading pkcs11 engine failed");
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* get all slots */
	rv = PKCS11_enumerate_slots(ctx, &slots, &nslots);
	if (rv) {
		pam_syslog(pamh, LOG_ERR, "listing slots failed");
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* search for the first slot with a token */
	slot = PKCS11_find_token(ctx, slots, nslots);
	if (!slot || !slot->token) {
		pam_syslog(pamh, LOG_ERR, "no token available");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	/* get all certs */
	rv = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
	if (rv) {
		pam_syslog(pamh, LOG_ERR, "PKCS11_enumerate_certs failed");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}
	if (ncerts <= 0) {
		pam_syslog(pamh, LOG_ERR, "no certificates found");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	/* find a valid and matching certificates */
	for (i = 0; i < ncerts; i++) {
		authcert = &certs[i];
		if (authcert != NULL) {
			/* check whether the certificate matches the user */
			rv = match_user(authcert->x509, user);
			if (rv < 0) {
				pam_syslog(pamh, LOG_ERR, "match_user() failed");
				rv = PAM_AUTHINFO_UNAVAIL;
				goto out;
			} else if (rv == 0) {
				/* this is not the cert we are looking for */
				authcert = NULL;
			} else {
				break;
			}
		}
	}

	if (!authcert) {
		pam_syslog(pamh, LOG_ERR, "not matching certificate found");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	if (!slot->token->loginRequired)
		goto loggedin;

	/* try to get stored item */
	rv = pam_get_item(pamh, PAM_AUTHTOK, (void *)&password);
	if (rv == PAM_SUCCESS && password) {
		password = strdup(password);
	} else {
		char text[80];
		const char *prompt;
		struct pam_message msg;
		msgp[0] = &msg;

		if (slot->token->secureLogin) {
			prompt = ": Enter PIN on PIN pad";
			msg.msg_style = PAM_TEXT_INFO;
		} else {
			prompt = ": Enter PIN: ";
			/* ask the user for the password if variable text is set */
			msg.msg_style = PAM_PROMPT_ECHO_OFF;
		}
		sprintf(text, "%.*s%s",
				sizeof text - strlen(prompt), slot->token->label, prompt);
		msg.msg = text;

		rv = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
		if (rv != PAM_SUCCESS) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto out;
		}
		if ((conv == NULL) || (conv->conv == NULL)) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto out;
		}
		rv = conv->conv(1, (const struct pam_message **)msgp, &resp,
				conv->appdata_ptr);
		if (rv != PAM_SUCCESS) {
			rv = PAM_AUTHINFO_UNAVAIL;
			goto out;
		}

		if (slot->token->secureLogin) {
			password = NULL;
		} else {
			if ((resp == NULL) || (resp[0].resp == NULL)) {
				rv = PAM_AUTHINFO_UNAVAIL;
				goto out;
			}
			password = strdup(resp[0].resp);
			/* overwrite memory and release it */
			memset(resp[0].resp, 0, strlen(resp[0].resp));
			free(&resp[0]);
		}
	}

	/* perform pkcs #11 login */
	rv = PKCS11_login(slot, 0, password);
	if (password) {
		memset(password, 0, strlen(password));
		free(password);
	}
	if (rv != 0) {
		pam_syslog(pamh, LOG_ERR, "PKCS11_login failed");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	/* login destroyed the certificates, get all certs */
	rv = PKCS11_enumerate_certs(slot->token, &certs, &ncerts);
	if (rv) {
		pam_syslog(pamh, LOG_ERR, "PKCS11_enumerate_certs failed");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}
	if (ncerts <= 0) {
		pam_syslog(pamh, LOG_ERR, "no certificates found");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	/* find a valid and matching certificates */
	for (i = 0; i < ncerts; i++) {
		authcert = &certs[i];
		if (authcert != NULL) {
			/* check whether the certificate matches the user */
			rv = match_user(authcert->x509, user);
			if (rv < 0) {
				pam_syslog(pamh, LOG_ERR, "match_user() failed");
				rv = PAM_AUTHINFO_UNAVAIL;
				goto out;
			} else if (rv == 0) {
				/* this is not the cert we are looking for */
				authcert = NULL;
			} else {
				break;
			}
		}
	}

	if (!authcert) {
		pam_syslog(pamh, LOG_ERR, "not matching certificate found");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

      loggedin:
	/* get random bytes */
	fd = open(RANDOM_SOURCE, O_RDONLY);
	if (fd < 0) {
		pam_syslog(pamh, LOG_ERR, "fatal: cannot open RANDOM_SOURCE: ");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	rv = read(fd, rand_bytes, RANDOM_SIZE);
	if (rv < 0) {
		pam_syslog(pamh, LOG_ERR, "fatal: read from random source failed: ");
		close(fd);
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	if (rv < RANDOM_SIZE) {
		pam_syslog(pamh, LOG_ERR, "fatal: read returned less than %d<%d bytes\n",
		       rv, RANDOM_SIZE);
		close(fd);
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	close(fd);

	authkey = PKCS11_find_key(authcert);
	if (!authkey) {
		pam_syslog(pamh, LOG_ERR, "no key matching certificate available");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	/* ask for a sha1 hash of the random data, signed by the key */
	siglen = MAX_SIGSIZE;
	rv = PKCS11_sign(NID_sha1, rand_bytes, RANDOM_SIZE, signature, &siglen,
			 authkey);
	if (rv != 1) {
		pam_syslog(pamh, LOG_ERR, "fatal: pkcs11_sign failed\n");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	/* verify the signature */
	pubkey = X509_get_pubkey(authcert->x509);
	if (pubkey == NULL) {
		pam_syslog(pamh, LOG_ERR, "could not extract public key");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	/* now verify the result */
	rsa = EVP_PKEY_get0_RSA(pubkey);
	if (rsa == NULL) {
		pam_syslog(pamh, LOG_ERR, "could not extract rsa public key\n");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}
	rv = RSA_verify(NID_sha1, rand_bytes, RANDOM_SIZE,
			signature, siglen, rsa);
	if (rv != 1) {
		pam_syslog(pamh, LOG_ERR, "fatal: RSA_verify failed\n");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	rv = PAM_SUCCESS;

out:
	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);
	if (pubkey)
		EVP_PKEY_free(pubkey);

	return rv;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
			      const char **argv)
{
	/* Actually, we should return the same value as pam_sm_authenticate(). */
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc,
				const char **argv)
{
	pam_syslog(pamh, LOG_WARNING,
	       "Function pam_sm_acct_mgmt() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags, int argc,
				   const char **argv)
{
	pam_syslog(pamh, LOG_WARNING,
	       "Function pam_sm_open_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
				    const char **argv)
{
	pam_syslog(pamh, LOG_WARNING,
	       "Function pam_sm_close_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc,
				const char **argv)
{
	pam_syslog(pamh, LOG_WARNING,
	       "Function pam_sm_chauthtok() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_group_modstruct = {
	"pam_p11",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};
#endif
