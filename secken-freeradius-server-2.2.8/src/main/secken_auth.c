#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/sha.h>

#include "cJSON.h"

#define STATE_SUCCESS 200

static void sha1_2_str(char *str, unsigned char *sha1)
{
	int i;

	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(str + (2 * i), "%02x", sha1[i]);

	return;
}

static size_t secken_auth_req_cb(
		char *buffer, 
		size_t size, 
		size_t nmemb, 
		void *ctx)
{
	char *event_id = (char *)ctx;
	cJSON *resp, *item;

	if (!ctx) {
		printf("%s: invalid input param.\n", __func__);
		goto done;
	}

	resp = cJSON_Parse(buffer);
	if (NULL == resp) {
		goto done;
	}

	item = cJSON_GetObjectItem(resp, "status");
	if ( NULL == item )
		goto result_err;

	if (item->valueint == STATE_SUCCESS) {
		item = cJSON_GetObjectItem(resp, "event_id" );
		if ( NULL != item ) 
			strcpy( event_id, item->valuestring );
	} else 
		sprintf(event_id, "%d", item->valueint);

result_err:
	cJSON_Delete(resp);
done:
	return size * nmemb;
}

int secken_auth_req(
		char *url, 
		char *power_id, 
		char *power_key, 
		char *username,
		char *event_id)
{
	CURLcode ret;
	CURL *curl;
	char buf[1024];
	char sig[64];
	unsigned char sha[SHA_DIGEST_LENGTH];

	curl = curl_easy_init();
	if (!curl) 
		return -1;

	memset(buf, 0, sizeof(buf));
	sprintf( buf, "power_id=%susername=%s%s", 
			power_id, username, power_key );

	memset(sha, 0, sizeof(sha));
	SHA1((unsigned char *)buf, strlen(buf), sha);
	sha1_2_str(sig, sha);
	//fprintf( stderr,"sig=%s\n", sig );

	memset(buf, 0, sizeof(buf));
	sprintf( buf, "power_id=%s&username=%s&signature=%s", 
			power_id, username, sig );
	//fprintf( stderr,"buf=%s\n", buf );

	curl_easy_setopt( curl, CURLOPT_URL, url ); 
	curl_easy_setopt( curl, CURLOPT_POSTFIELDS, buf );
	curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, secken_auth_req_cb );
	curl_easy_setopt( curl, CURLOPT_WRITEDATA, (void *)event_id );
	curl_easy_setopt( curl, CURLOPT_POST, 1 );

	ret = curl_easy_perform( curl );

	curl_easy_cleanup( curl );

	return ret;
}

static size_t secken_event_req_cb(
		char *buffer, 
		size_t size, 
		size_t nmemb, 
		void *ctx)
{
	int *status = (int *)ctx; 
	cJSON *resp, *item;

	if (!ctx) {
		printf("%s: invalid input param.\n", __func__);
		goto done;
	}

	resp = cJSON_Parse(buffer);
	if (NULL == resp) {
		goto done;
	}

	*status = -1;
	item = cJSON_GetObjectItem(resp, "status");
	if ( NULL == item )
		goto result_err;

	*status = item->valueint;

result_err:
	cJSON_Delete(resp);
done:
	return size * nmemb;
}

int secken_event_req(
		char *url, 
		char *power_id, 
		char *power_key, 
		char *event_id,
		int *status)
{
	CURLcode ret;
	CURL *curl;
	char buf[1024];
	char sig[64];
	unsigned char sha[SHA_DIGEST_LENGTH];

	curl = curl_easy_init();
	if (!curl) 
		return -1;

	memset(buf, 0, sizeof(buf));
	sprintf( buf, "event_id=%spower_id=%s%s", 
			event_id, power_id, power_key );
//	fprintf( stderr,"ori_sig=%s\n", buf );

	memset(sha, 0, sizeof(sha));
	SHA1((unsigned char *)buf, strlen(buf), sha);
	sha1_2_str(sig, sha);
//	fprintf( stderr,"sig=%s\n", sig );

	memset(buf, 0, sizeof(buf));
	sprintf( buf, "event_id=%s&power_id=%s&signature=%s", 
			event_id, power_id, sig );
//	fprintf( stderr,"buf=%s\n", buf );

	curl_easy_setopt( curl, CURLOPT_URL, url ); 
	curl_easy_setopt( curl, CURLOPT_POSTFIELDS, buf );
	curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, secken_event_req_cb );
	curl_easy_setopt( curl, CURLOPT_WRITEDATA, (void *)status );
	curl_easy_setopt( curl, CURLOPT_POST, 1 );

	ret = curl_easy_perform( curl );

	curl_easy_cleanup( curl );

	return ret;
}
