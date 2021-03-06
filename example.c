#include <stdlib.h>
#include "signer.h"
#include <curl/curl.h>

/* compilation: cc -std=gnu11 example.c -lcurl  -lcrypto -I/openssl/include/path */

int main(void)
{
	cwv4_autofree char *r = NULL;
	CURL *c = curl_easy_init();
	char date_iso[24];
	char date_str[64];
	const char *data = "";
	struct curl_slist *list = NULL;

	if (!c)
	  return -1;

	struct cwv4_signer s = {
		CWV4_POST,
		"MY AK", /* change my ak with you access key */
		"MY SK", /* change my sk with you secret key */
		"api.eu-west-2.outscale.com",
		"eu-west-2"
	};
	cwv4_mk_date(date_iso);
	printf("host: %s\ndate %s\n", s.host, date_iso);
	r = cwv4_auth_hdr(&s, "/api/latest/ReadVms", data, date_iso);
	printf("%s\n", r);
	sprintf(date_str, "X-Osc-Date: %s", date_iso);

	CURLcode res;
	/* curl_easy_setopt(c, CURLOPT_URL, */
	/* 		 "https://api.eu-west-2.outscale.com/api/latest/ReadVms"); */
	/* curl_easy_setopt(c, CURLOPT_VERBOSE, 1L); */

	/* curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)strlen(data)); */
	/* curl_easy_setopt(c, CURLOPT_POSTFIELDS, data); */

	/* list = curl_slist_append(list, "Content-Type: application/json; charset=utf-8"); */
	/* list = curl_slist_append(list, "Accept: application/json"); */
	/* list = curl_slist_append(list, date_str); */
	/* list = curl_slist_append(list, r); */
	/* curl_easy_setopt(c, CURLOPT_HTTPHEADER, list); */
	/* res = curl_easy_perform(c); */
	/* curl_easy_cleanup(c); */

	char *tmp;
	CWV4_SPRINTF(tmp, "curl -X POST https://api.eu-west-2.outscale.com/api/latest/ReadVms "
		     "-H 'Content-Type: application/json; charset=utf-8' "
		     "-H 'Accept: application/json' "
		     "-H '%s' "
		     "-H '%s' -d ''", date_str, r);
	printf("\ndo: %s\n", tmp);
	system(tmp);
	free(tmp);
	return 0;
}
