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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <syslog.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/crypto.h>

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
static int pam_vprompt(pam_handle_t *pamh, int style, char **response,
		const char *fmt, va_list args)
{
	int r = PAM_CRED_INSUFFICIENT;
	const struct pam_conv *conv;
	struct pam_message msg;
	struct pam_response *resp = NULL;
	struct pam_message *(msgp[1]);

	char text[128];
	vsnprintf(text, sizeof text, fmt, args);

	msgp[0] = &msg;
	msg.msg_style = style;
	msg.msg = text;

	if (PAM_SUCCESS != pam_get_item(pamh, PAM_CONV, (const void **) &conv)
		|| NULL == conv || NULL == conv->conv
		|| conv->conv(1, (const struct pam_message **) msgp, &resp, conv->appdata_ptr)
		|| NULL == resp) {
		goto err;
	}
	if (NULL != response) {
		if (resp[0].resp) {
			*response = strdup(resp[0].resp);
			if (NULL == *response) {
				pam_syslog(pamh, LOG_CRIT, "strdup() failed: %s",
						strerror(errno));
				goto err;
			}
		} else {
			*response = NULL;
		}
	}

	r = PAM_SUCCESS;
err:
	if (resp) {
		OPENSSL_cleanse(&resp[0].resp, sizeof resp[0].resp);
		free(&resp[0]);
	}
	return r;
}
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

extern int match_user_opensc(EVP_PKEY *authkey, const char *login);
extern int match_user_openssh(EVP_PKEY *authkey, const char *login);

int prompt(int flags, pam_handle_t *pamh, int style, char **response,
			    const char *fmt, ...)
{
	int r;

	if (PAM_SILENT == (flags & PAM_SILENT)) {
		r = PAM_SUCCESS;
	} else {
		va_list args;
		va_start (args, fmt);
		r = pam_vprompt(pamh, style, response, fmt, args);
		va_end(args);
	}

	return r;
}

static int key_login(pam_handle_t *pamh, int flags, PKCS11_SLOT *slot)
{
	char *password = NULL;
	int ok = 0;

	if (0 == slot->token->loginRequired) {
		ok = 1;
		goto err;
	}

	/* try to get stored item */
	if (PAM_SUCCESS == pam_get_item(pamh, PAM_AUTHTOK, (void *)&password)
			&& NULL != password) {
		password = strdup(password);
		if (NULL == password) {
			pam_syslog(pamh, LOG_CRIT, "strdup() failed: %s",
					strerror(errno));
			goto err;
		}
	} else {
		const char *pin_info;

		if (slot->token->userPinFinalTry) {
			pin_info = " (last try)";
		} else {
			pin_info = "";
		}

		if (0 != slot->token->secureLogin) {
			prompt(flags, pamh, PAM_TEXT_INFO, NULL,
					"Login on PIN pad with %s%s",
					slot->token->label, pin_info);
		} else {
			/* ask the user for the password if variable text is set */
			if (PAM_SUCCESS != prompt(flags, pamh,
						PAM_PROMPT_ECHO_OFF, &password,
						"Login with %s%s: ",
						slot->token->label, pin_info)) {
				goto err;
			}
		}
	}

	if (0 != PKCS11_login(slot, 0, password) != 0) {
		if (slot->token->userPinLocked) {
			prompt(flags, pamh, PAM_ERROR_MSG, NULL, "PIN not verified; PIN locked");
		} else if (slot->token->userPinFinalTry) {
			prompt(flags, pamh, PAM_ERROR_MSG, NULL, "PIN not verified; one try remaining");
		} else {
			prompt(flags, pamh, PAM_ERROR_MSG, NULL, "PIN not verified");
		}
		goto err;
	}

	ok = 1;

err:
	if (NULL != password) {
		OPENSSL_cleanse(password, strlen(password));
		free(password);
	}

	return ok;
}

static int key_find(pam_handle_t * pamh, int flags, const char *user,
		PKCS11_CTX *ctx, PKCS11_SLOT *slots, unsigned int nslots,
		PKCS11_SLOT **authslot, PKCS11_KEY **authkey)
{
	int token_found = 0;

	if (NULL == authslot || NULL == authkey) {
		return 0;
	}

	*authkey = NULL;
	*authslot = NULL;

	while (0 < nslots) {
		PKCS11_SLOT *slot = NULL;
		PKCS11_CERT *certs = NULL;
		PKCS11_KEY *keys = NULL;
		unsigned int count = 0;

		slot = PKCS11_find_token(ctx, slots, nslots);
		if (NULL == slot || NULL == slot->token) {
			break;
		}
		token_found = 1;

		if (slot->token->loginRequired && slot->token->userPinLocked) {
			pam_syslog(pamh, LOG_DEBUG, "%s: PIN locked",
					slot->token->label);
			continue;
		}
		pam_syslog(pamh, LOG_DEBUG, "Searching %s for keys",
				slot->token->label);

		if (0 == PKCS11_enumerate_public_keys(slot->token, &keys, &count)) {
			while (0 < count && NULL != keys) {
				EVP_PKEY *pubkey = PKCS11_get_public_key(keys);
				int r = match_user_opensc(pubkey, user);
				if (1 != r) {
					r = match_user_openssh(pubkey, user);
				}
				if (NULL != pubkey) {
					EVP_PKEY_free(pubkey);
				}
				if (1 == r) {
					*authkey = keys;
					*authslot = slot;
					pam_syslog(pamh, LOG_DEBUG, "Found %s",
							keys->label);
					return 1;
				}

				/* Try the next possible public key */
				keys++;
				count--;
			}
		}

		if (0 == PKCS11_enumerate_certs(slot->token, &certs, &count)) {
			while (0 < count && NULL != certs) {
				EVP_PKEY *pubkey = X509_get_pubkey(certs->x509);
				int r = match_user_opensc(pubkey, user);
				if (1 != r) {
					r = match_user_openssh(pubkey, user);
				}
				if (NULL != pubkey) {
					EVP_PKEY_free(pubkey);
				}
				if (1 == r) {
					*authkey = PKCS11_find_key(certs);
					if (NULL == *authkey) {
						continue;
					}
					*authslot = slot;
					pam_syslog(pamh, LOG_DEBUG, "Found %s",
							certs->label);
					return 1;
				}

				/* Try the next possible certificate */
				certs++;
				count--;
			}
		}

		/* Try the next possible slot: PKCS11 slots are implemented as array,
		 * so starting to look at slot++ and decrementing nslots accordingly
		 * will search the rest of slots. */
		slot++;
		nslots -= (slot - slots);
		slots = slot;
		pam_syslog(pamh, LOG_DEBUG, "No authorized key found");
	}

	if (0 == token_found) {
		prompt(flags, pamh, PAM_ERROR_MSG , NULL, "No token found");
	} else {
		prompt(flags, pamh, PAM_ERROR_MSG , NULL, "No authorized keys on token");
	}

	return 0;
}

static int randomize(pam_handle_t *pamh, unsigned char *r, unsigned int r_len)
{
	int ok = 0;
	int fd = open("/dev/urandom", O_RDONLY);
	if (0 <= fd && read(fd, r, r_len) == r_len) {
		ok = 1;
	} else {
		pam_syslog(pamh, LOG_CRIT, "Error reading from /dev/urandom: %s",
				strerror(errno));
	}
	if (0 < fd) {
		close(fd);
	}
	return ok;
}

static int key_verify(pam_handle_t *pamh, int flags, PKCS11_KEY *authkey)
{
	int ok = 0;
	unsigned char challenge[30];
	unsigned char signature[256];
	unsigned int siglen = sizeof signature;
	const EVP_MD *md = EVP_sha1();
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
	EVP_PKEY *privkey = PKCS11_get_private_key(authkey);
	EVP_PKEY *pubkey = PKCS11_get_public_key(authkey);

	/* verify a sha1 hash of the random data, signed by the key */
	if (1 != randomize(pamh, challenge, sizeof challenge)) {
		goto err;
	}
	if (NULL == pubkey || NULL == privkey || NULL == md_ctx || NULL == md
			|| !EVP_SignInit(md_ctx, md)
			|| !EVP_SignUpdate(md_ctx, challenge, sizeof challenge)
			|| !EVP_SignFinal(md_ctx, signature, &siglen, privkey)
			|| !EVP_MD_CTX_cleanup(md_ctx)
			|| !EVP_VerifyInit(md_ctx, md)
			|| !EVP_VerifyUpdate(md_ctx, challenge, sizeof challenge)
			|| 1 != EVP_VerifyFinal(md_ctx, signature, siglen, pubkey)) {
		ERR_load_crypto_strings();
		pam_syslog(pamh, LOG_DEBUG, "Error verifying key: %s\n",
				ERR_reason_error_string(ERR_get_error()));
		prompt(flags, pamh, PAM_ERROR_MSG, NULL, "Error verifying key");
		goto err;
	}
	ok = 1;

err:
	if (NULL != pubkey)
		EVP_PKEY_free(pubkey);
	if (NULL != privkey)
		EVP_PKEY_free(privkey);
	if (NULL != md_ctx) {
		EVP_MD_CTX_destroy(md_ctx);
	}
	return ok;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
				   const char **argv)
{
	const char *user;
	int r;
	unsigned int nslots = 0;
	PKCS11_CTX *ctx = NULL;
	PKCS11_SLOT *authslot = NULL, *slots = NULL;
	PKCS11_KEY *authkey;

	/* get user name */
	r = pam_get_user(pamh, &user, NULL);
	if (PAM_SUCCESS != r) {
		pam_syslog(pamh, LOG_ERR, "pam_get_user() failed %s",
		       pam_strerror(pamh, r));
		return PAM_USER_UNKNOWN;
	}

	/* Initialize OpenSSL */
	OpenSSL_add_all_algorithms();

	/* Load and initialize PKCS#11 module */
	ctx = PKCS11_CTX_new();
	if (1 != argc || NULL == ctx || 0 != PKCS11_CTX_load(ctx, argv[0])) {
		ERR_load_crypto_strings();
		pam_syslog(pamh, LOG_ALERT, "Loading PKCS#11 engine failed: %s\n",
				ERR_reason_error_string(ERR_get_error()));
		prompt(flags, pamh, PAM_ERROR_MSG , NULL, "Error loading PKCS#11 module");
		r = PAM_NO_MODULE_DATA;
		goto err_not_loaded;
	}
	if (0 != PKCS11_enumerate_slots(ctx, &slots, &nslots)) {
		ERR_load_crypto_strings();
		pam_syslog(pamh, LOG_ALERT, "Initializing PKCS#11 engine failed: %s\n",
				ERR_reason_error_string(ERR_get_error()));
		prompt(flags, pamh, PAM_ERROR_MSG , NULL, "Error initializing PKCS#11 module");
		r = PAM_AUTHINFO_UNAVAIL;
		goto err;
	}

	if (1 != key_find(pamh, flags, user, ctx, slots, nslots,
				&authslot, &authkey)) {
		r = PAM_AUTHINFO_UNAVAIL;
		goto err;
	}
	if (1 != key_login(pamh, flags, authslot)
			|| 1 != key_verify(pamh, flags, authkey)) {
		if (authslot->token->userPinLocked) {
			r = PAM_MAXTRIES;
		} else {
			r = PAM_AUTH_ERR;
		}
		goto err;
	}

	r = PAM_SUCCESS;

err:
	PKCS11_release_all_slots(ctx, slots, nslots);
	PKCS11_CTX_unload(ctx);
err_not_loaded:
	PKCS11_CTX_free(ctx);

	return r;
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
	pam_syslog(pamh, LOG_DEBUG,
	       "Function pam_sm_acct_mgmt() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags, int argc,
				   const char **argv)
{
	pam_syslog(pamh, LOG_DEBUG,
	       "Function pam_sm_open_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
				    const char **argv)
{
	pam_syslog(pamh, LOG_DEBUG,
	       "Function pam_sm_close_session() is not implemented in this module");
	return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc,
				const char **argv)
{
	pam_syslog(pamh, LOG_DEBUG,
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
