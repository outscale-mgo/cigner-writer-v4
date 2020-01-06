/* Copyright (c) 2020 OUTSCALE SAS. All rights reserved. */

/* Redistribution and use in source and binary forms, with or without modification, */
/* are permitted provided that the following conditions are met: */

/* 1. Redistributions of source code must retain the above copyright notice, */
/* this list of conditions and the following disclaimer. */

/* 2. Redistributions in binary form must reproduce the above copyright notice, */
/* this list of conditions and the following disclaimer in the documentation */
/* and/or other materials provided with the distribution. */

/* 3. Neither the name of the copyright holder nor the names of its contributors */
/* may be used to endorse or promote products derived from this software without */
/* specific prior written permission. */

/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" */
/* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE */
/* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE */
/* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE */
/* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL */
/* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR */
/* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER */
/* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, */
/* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE */
/* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

/*
 * GNU C11 header only library that does V4 signature
 * rely on OpenSSL
 */

#ifndef CWV4_SIGNER__
#define CWV4_SIGNER__

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>

#include <stdlib.h>
#include <time.h>

#include <string.h>


#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

/*
  # Step 1 is to define the verb (GET, POST, etc.)--already done.
  # Step 2: Create canonical URI--the part of the URI from domain to query
  #         string (use '/' if no path)
  #         canonical_uri = '/'
  # Step 3: Create the canonical query string. In this example, request
  #         parameters are passed in the body of the request and the query string
  #         is blank.
  # Step 4: Create the canonical headers. Header names must be trimmed
  #         and lowercase, and sorted in code point order from low to high.
  #         Note that there is a trailing \n.
  # Step 5: Create the list of signed headers. This lists the headers
  #         in the canonical_headers list, delimited with ";" and in alpha order.
  #         Note: The request can include any headers; canonical_headers and
  #         signed_headers include those that you want to be included in the
  #         hash of the request. "Host" and "x-amz-date" are always required.
  # Step 6: Create payload hash. In this example, the payload (body of
  #         the request) contains the request parameters.
  # Step 7: Combine elements to create canonical request
*/

enum cwv4_request_type {
	CWV4_POST,
	CWV4_GET
};

enum cwv4_algo {
	CWV4_SHA256,
};

struct cwv4_signer {
	enum cwv4_request_type t;
	char ak[21];
	char sk[41];
	char *host;
	char *region;
};

#define cwv4_autofree __attribute__((__cleanup__(cwv4_autofree_)))

static inline void cwv4_autofree_(void *p)
{
	void **pp = p;

	free(*pp);
}

static inline char *cwv4_digest_str(const unsigned char *digest, char rbuf[static 65])
{
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		sprintf(rbuf + (i * 2), "%02x", digest[i]);
	}
	rbuf[64] = 0;
	return rbuf;
}

#define CWV4_SPRINTF(str, fmt, args...)					\
	if (asprintf(&str, fmt, args) < 0) { str = NULL; return NULL; }

#define cwv4_sha256(str)			\
	cwv4_sha256_(str, (char[65]){0})

static const char *cwv4_sha256_(const char *str, char *rbuf)
{
	unsigned char sha_digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha_ctx;
	
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, str, strlen(str));
	SHA256_Final(sha_digest, &sha_ctx);
	return cwv4_digest_str(sha_digest, rbuf);
}

#define cwv4_hmac(str, k, kl)			\
	cwv4_hmac_(str, k, kl, (unsigned char [SHA256_DIGEST_LENGTH]){0});

static unsigned char *cwv4_hmac_(const char *str, void *k, int kl, void *rbuf)
{
	HMAC_CTX hmac_ctx;
	unsigned int hmac_sha_l;

/*
 * HMAC_CTX_init was rename on recent openssl,
 * so we need a C preprocessor branch here
 * with some testing on Arch Linux
 */
	HMAC_CTX_init(&hmac_ctx);
	HMAC_Init_ex(&hmac_ctx, k, kl, EVP_sha256(), NULL);
	HMAC_Update(&hmac_ctx, (unsigned char *)str, strlen(str));
	HMAC_Final(&hmac_ctx, rbuf, &hmac_sha_l);
	HMAC_CTX_cleanup(&hmac_ctx);
	return rbuf;
}

static void cwv4_clean_ssl(void)
{
	ERR_free_strings ();
	RAND_cleanup ();
	EVP_cleanup ();
	CONF_modules_free ();
	ERR_remove_state (0);
}

static void cwv4_init_ssl(void)
{
	ERR_load_crypto_strings ();
	OpenSSL_add_all_algorithms ();
	OPENSSL_config (NULL);
}

static char *cwv4_mk_date(char date_iso[static 17])
{
#ifndef FAKE_DATE
	struct tm *info;
	time_t rawtime;

	time(&rawtime);
	info = localtime(&rawtime);

	if (!strftime(date_iso, 256, "%Y%m%dT%H%M%SZ", info))
		return NULL;
#else
	strcpy(date_iso, "20200103T175243Z");
#endif
	return date_iso;
}

static char *cwv4_auth_hdr(struct cwv4_signer *signer, const char *uri,
			   const char *request_data, char date_iso[static 17])
{
	char date[9];
	cwv4_autofree char *credential_scope = NULL;
	cwv4_autofree char *credential_request = NULL;
	cwv4_autofree char *canonical_headers = NULL;
	cwv4_autofree char *str_to_sign = NULL;
	char osc_sk[45] = "OSC4"; /* sk len + strlen("OSC4") */
	cwv4_autofree char *authorisation = NULL;
	char signature[65]; /* a sha256 hex digest */
	unsigned char *tmp_sign;
	char *ret;

	memcpy(date, date_iso, 8);
	date[8] = 0;
	CWV4_SPRINTF(credential_scope, "%s/%s/api/osc4_request",
		     date, signer->region);

	CWV4_SPRINTF(canonical_headers,
		     "content-type:application/json; charset=utf-8\n"
		     "host:%s\n"
		     "x-osc-date:%s\n", signer->host, date_iso);

	CWV4_SPRINTF(credential_request,
		     "%s\n" /* Methode */
		     "%s\n" /* uri */
		     "\n" /* querystring ? */
		     "%s\n" /* canonical_headers */
		     "content-type;host;x-osc-date\n" /* signed header */
		     "%s" /* SHA SHA SHA ! */,
		     signer->t == CWV4_POST ? "POST" : "GET",
		     uri, canonical_headers, cwv4_sha256(request_data));

	CWV4_SPRINTF(str_to_sign, "OSC4-HMAC-SHA256\n"
		     "%s\n" /* date iso */
		     "%s\n"/* credential_scope */
		     "%s", /* SHA ga kuru */
		     date_iso, credential_scope, cwv4_sha256(credential_request));

	strncpy(osc_sk + 4, signer->sk, 40);
	osc_sk[44] = 0;
	tmp_sign = cwv4_hmac(date, osc_sk, 44);
	tmp_sign = cwv4_hmac(signer->region, tmp_sign, SHA256_DIGEST_LENGTH);
	tmp_sign = cwv4_hmac("api", tmp_sign, SHA256_DIGEST_LENGTH);
	tmp_sign = cwv4_hmac("osc4_request", tmp_sign, SHA256_DIGEST_LENGTH);
	tmp_sign = cwv4_hmac(str_to_sign, tmp_sign, SHA256_DIGEST_LENGTH);

	CWV4_SPRINTF(authorisation, "OSC4-HMAC-SHA256 Credential=%s/%s, "
		     "SignedHeaders=content-type;host;x-osc-date, Signature=%s",
		     signer->ak, credential_scope, cwv4_digest_str(tmp_sign, signature));

	CWV4_SPRINTF(ret, "Authorization: %s\n", authorisation);
	return ret;
}

#endif
