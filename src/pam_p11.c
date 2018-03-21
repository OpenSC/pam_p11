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

static int pam_prompt(pam_handle_t *pamh, int style, char **response, const char *text)
{
	int rv;
	const struct pam_conv *conv;
	struct pam_message msg;
	struct pam_response *resp;
	struct pam_message *(msgp[1]);
	msgp[0] = &msg;

	msg.msg_style = style;
	msg.msg = text;
	rv = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if (rv != PAM_SUCCESS)
		return rv;
	if ((conv == NULL) || (conv->conv == NULL))
		return PAM_CRED_INSUFFICIENT;
	rv = conv->conv(1, (const struct pam_message **) msgp, &resp, conv->appdata_ptr);
	if (rv != PAM_SUCCESS)
		return rv;
	if ((resp == NULL) || (resp[0].resp == NULL))
		return !response ? PAM_SUCCESS : PAM_CRED_INSUFFICIENT;
	if (response) {
		*response = strdup(resp[0].resp);
	}
	/* overwrite memory and release it */
	memset(resp[0].resp, 0, strlen(resp[0].resp));
	free(&resp[0]);
	return PAM_SUCCESS;
}

static int login(pam_handle_t *pamh, PKCS11_SLOT *slot)
{
	char *password = NULL;
	int ok = 0;

	if (!slot->token->loginRequired) {
		ok = 1;
		goto out;
	}

	/* try to get stored item */
	if (pam_get_item(pamh, PAM_AUTHTOK, (void *)&password) == PAM_SUCCESS
			&& password) {
		password = strdup(password);
	} else {
		char text[80];
		const char *prompt;
		char **response;
		int msg_style;

		if (slot->token->secureLogin) {
			prompt = ": Enter PIN on PIN pad";
			msg_style = PAM_TEXT_INFO;
			response = NULL;
		} else {
			prompt = ": Enter PIN: ";
			/* ask the user for the password if variable text is set */
			msg_style = PAM_PROMPT_ECHO_OFF;
			response = &password;
		}
		sprintf(text, "%.*s%s",
				sizeof text - strlen(prompt), slot->token->label, prompt);
		if (pam_prompt(pamh, msg_style, response, text) != PAM_SUCCESS) {
			goto out;
		}
	}

	/* perform pkcs #11 login */
	if (PKCS11_login(slot, 0, password) != 0) {
		pam_prompt(pamh, PAM_ERROR_MSG, NULL, "Error verifying PIN");
		goto out;
	}

	ok = 1;

out:
	if (password) {
		memset(password, 0, strlen(password));
		free(password);
	}

	return ok;
}

static int randomize(unsigned char *r, size_t r_len)
{
	int ok = 0;

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0 || read(fd, r, r_len) != r_len) {
		pam_syslog(pamh, LOG_ERR, "fatal: failed to read from /dev/urandom: %s",
				strerror(errno));
		goto out;
	}

out:
	if (fd > 0)
		close(fd);

	return ok;
}

static int sign(EVP_MD_CTX *md_ctx, const EVP_MD *md,
	const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, PKCS11_KEY *key)
{
	int ok = 0;

	EVP_PKEY *privkey = PKCS11_get_private_key(key);

	if (!EVP_SignInit(md_ctx, md)
			|| !EVP_SignUpdate(md_ctx, m, m_len)
			|| !EVP_SignFinal(md_ctx, sigret, siglen, privkey)) {
		pam_syslog(pamh, LOG_ERR, "Signing failed: %s\n",
				ERR_reason_error_string(ERR_get_error()));
		goto err;
	}

	ok = 1;

err:
	if (privkey != NULL)
		EVP_PKEY_free(privkey);
	if (md_ctx != NULL) {
		EVP_MD_CTX_destroy(md_ctx);
	}

	return ok;
}

static int verify(EVP_MD_CTX *md_ctx, const EVP_MD *md,
	const unsigned char *m, unsigned int m_len,
	unsigned char *signature, unsigned int siglen, PKCS11_CERT *cert)
{
	int ok = 0;

	EVP_PKEY *pubkey = X509_get_pubkey(cert->x509);

	if (!EVP_VerifyInit(md_ctx, md)
			|| !EVP_VerifyUpdate(md_ctx, m, m_len)
			|| 1 != EVP_VerifyFinal(md_ctx, signature, siglen, pubkey)) {
		pam_syslog(pamh, LOG_ERR, "Verifying failed: %s\n",
				ERR_reason_error_string(ERR_get_error()));
		goto err;
	}

	ok = 1;

err:
	if (pubkey != NULL)
		EVP_PKEY_free(pubkey);

	return ok;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
				   const char **argv)
{
	int rv;
	const char *user;

	PKCS11_CTX *ctx;
	PKCS11_SLOT *slot, *slots;
	PKCS11_CERT *certs;
	unsigned int nslots, ncerts;
	PKCS11_KEY *authkey;
	PKCS11_CERT *authcert;

	RSA *rsa;
	EVP_MD_CTX *md_ctx = NULL;

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

	/* get user name */
	rv = pam_get_user(pamh, &user, NULL);
	if (rv != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user() failed %s",
		       pam_strerror(pamh, rv));
		return PAM_USER_UNKNOWN;
	}

	/* init openssl */
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* load pkcs #11 module */
	ctx = PKCS11_CTX_new();
	if (!ctx
			|| !PKCS11_CTX_load(ctx, argv[0])
			|| !PKCS11_enumerate_slots(ctx, &slots, &nslots)) {
		pam_syslog(pamh, LOG_ERR, "Initializing pkcs11 engine failed: %s\n",
				ERR_reason_error_string(ERR_get_error()));
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, "Error initializing PKCS#11 module");
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* search for the first slot with a token */
	slot = PKCS11_find_token(ctx, slots, nslots);
	if (!slot || !slot->token) {
		pam_prompt(pamh, PAM_ERROR_MSG , NULL, "No smart card found");
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
		pam_prompt(pamh, PAM_ERROR_MSG, NULL, "No authorized credential found");
		rv = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	/* verify a sha1 hash of the random data, signed by the key */
	siglen = MAX_SIGSIZE;
	md_ctx = EVP_MD_CTX_create();
	if (!randomize(rand_bytes, RANDOM_SIZE)
			|| !login(pamh, slot)
			|| !sign(md_ctx, EVP_sha1(), rand_bytes, RANDOM_SIZE, signature, &siglen,
				PKCS11_find_key(authcert))
			|| !verify(md_ctx, EVP_sha1(), rand_bytes, RANDOM_SIZE, signature,
				siglen, authcert)) {
		rv = PAM_AUTH_ERR;
		goto out;
	}

	rv = PAM_SUCCESS;

out:
	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
	PKCS11_CTX_free(ctx);
	if (md_ctx != NULL) {
		EVP_MD_CTX_destroy(md_ctx);
	}

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
