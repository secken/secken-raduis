#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/rad_assert.h>

#include "external.h"
#include "secken_auth.h"
#include "ccl.h"
#include "list.h"
#include "secken_user_list.h"

static int g_result_interval = 1;
static int g_timeout = 30;
static char g_auth_url[1024];
static char g_result_url[1024];
static char g_power_id[128];
static char g_power_key[128];
static int g_accept_cache_enable = 0;
static int g_accept_cache_time;
static int g_accept_cache_retry;

#define SK_RESULT_SUCCESS  1
#define SK_RESULT_FAILED   0

#define STATE_IN_AUTH  0
#define STATE_ACCEPTED 1

struct fr_event_t {
	fr_event_callback_t	callback;
	void				*ctx;
	struct timeval		when;
	fr_event_t			**ev_p;
	int					heap;
};

typedef struct _auth_handle_t
{
	char username[1024];
	fr_event_list_t *el;
	fr_event_t *ev;
	int time_count;
	int interval;
	char event_id[64];
	char secret[1024];
	RADIUS_PACKET packet;
	RADIUS_PACKET reply;
	int state;
	int retry_count;
} auth_handle_t;

typedef struct _accept_handle_t
{
	char username[1024];
	fr_event_list_t *el;
	fr_event_t *ev;
} accept_handle_t;

static int is_digit_str(const char *s)
{
	while(*s) 
		if(!isdigit(*s++))
			return 0;

	return 1;
}

static void copy_val_pair(RADIUS_PACKET *dst, RADIUS_PACKET *src)
{
	VALUE_PAIR *pos;
	VALUE_PAIR *new;

	dst->vps = NULL;
	for (pos = src->vps; pos != NULL; pos = pos->next) {
		new = (VALUE_PAIR *)malloc(sizeof(VALUE_PAIR));
		memcpy(new, pos, sizeof(VALUE_PAIR));
		new->next = NULL;
		pairadd(&dst->vps, new);
	}
}

static void del_val_pair(RADIUS_PACKET *pkt)
{
	pairfree(&pkt->vps);
}

static int auth_hdl_comp(void *src, void *dst)
{
	auth_handle_t *src_hdl = (auth_handle_t *)src;
	auth_handle_t *dst_hdl = (auth_handle_t *)dst;

	if (0 == strcmp(src_hdl->username, dst_hdl->username))
		return 1;

	return 0;
}

static int is_radiusd_ext_time_out(int t_count)
{
	if ( t_count > g_timeout )
		return 1;
	return 0;
}

static auth_handle_t* radiusd_ext_create_data(
		fr_event_list_t *el, 
		REQUEST *request,
		char *event_id)
{
	auth_handle_t *hdl = NULL;

	hdl = (auth_handle_t *)malloc(sizeof(auth_handle_t));
	if (NULL == hdl) 
		return NULL;
	memset(hdl, 0, sizeof(auth_handle_t));

	hdl->el = el;
	hdl->time_count = 0; // count the time this hdl we has pass
	hdl->interval = g_result_interval;
	hdl->ev = (fr_event_t *)malloc(sizeof(fr_event_t));
	memset(hdl->ev, 0, sizeof(struct fr_event_t));

	strncpy(hdl->event_id, event_id, sizeof(hdl->event_id) - 1);
	strncpy(hdl->username, request->username->data.strvalue, 
			sizeof(hdl->username) - 1);
	strncpy(hdl->secret, request->client->secret, 
			sizeof(hdl->secret) - 1);

	memcpy(&hdl->reply, request->reply, sizeof(RADIUS_PACKET));
	copy_val_pair(&hdl->reply, request->reply);

	memcpy(&hdl->packet, request->packet, sizeof(RADIUS_PACKET));	
	copy_val_pair(&hdl->packet, request->packet);

	hdl->retry_count = 0;

	return hdl;
}

static void radiusd_ext_del_data( auth_handle_t *hdl )
{
	del_val_pair( &hdl->packet );
	del_val_pair( &hdl->reply );

	if (hdl != NULL)
		free(hdl);
}

static void accepted_user_timer_cb(void *ctx)
{
	auth_handle_t *hdl = (auth_handle_t *)ctx;

	/* timer delete */
	fr_event_delete(hdl->el, &hdl->ev);

	radlog(L_INFO, "[%s] accepted timeout.\n", hdl->username);

	ulist_del(hdl, auth_hdl_comp);
	radiusd_ext_del_data( hdl );

	return;
}

static void accept_user(auth_handle_t *hdl)
{
	struct timeval when;

	hdl->state = STATE_ACCEPTED;
	fr_event_now(hdl->el, &when);
	when.tv_sec += g_accept_cache_time;
	when.tv_usec += 0;

	fr_event_insert(hdl->el, accepted_user_timer_cb, hdl, &when, &hdl->ev);

	radlog(L_INFO, "[%s] change to accepted.\n", hdl->username);

	return;
}

static int radiusd_send_back(
		int result,
		RADIUS_PACKET *reply, 
		const RADIUS_PACKET *packet,
		const char *secret )
{
	if (SK_RESULT_SUCCESS == result)
		reply->code = PW_AUTHENTICATION_ACK;
	if (SK_RESULT_FAILED == result)
		reply->code = PW_AUTHENTICATION_REJECT;

	return rad_send(reply, packet, secret);
}

static int radiusd_ext_send_back(
		int result, 
		auth_handle_t *hdl )
{
	if (SK_RESULT_FAILED == result)
		DEBUG("[EXTERNAL] recv Accept FAILED form secken \n");
	if (SK_RESULT_SUCCESS == result)
		DEBUG("[EXTERNAL] recv Accept SUCCESS form secken \n");

	return radiusd_send_back( result ,&hdl->reply, &hdl->packet, hdl->secret );
}

static int radiusd_ext_add_timer(
		auth_handle_t *hdl,
		fr_event_callback_t timer_cb )
{
	struct timeval when;

	hdl->time_count += hdl->interval;

	fr_event_now(hdl->el, &when);
	when.tv_sec += hdl->interval;
	when.tv_usec += 0;

	return fr_event_insert(hdl->el, timer_cb, hdl, &when, &hdl->ev);
}

static void radiusd_ext_do_auth_timer_cb(void *ctx)
{
	int status;
	int result;
	char *event_id;
	char err_buf[2048];
	char username[1024];
	auth_handle_t *hdl = (auth_handle_t*)ctx;

	memset(err_buf, 0, sizeof(err_buf));
	strcpy(username, hdl->username);

	/* timer delete */
	fr_event_delete(hdl->el, &hdl->ev);

	event_id = hdl->event_id;

	if ( is_radiusd_ext_time_out(hdl->time_count) ) {
		/* this auth timeout */
		result = SK_RESULT_FAILED;
		radlog(L_INFO, "[%s] time out.\n", username);
		strcpy(err_buf, "time out");
		goto send_result;
	}

	if ( 0 == secken_event_req(g_result_url, g_power_id, g_power_key, 
				event_id, &status ) ) {
		if ( 200 == status ) {
			/* status == 200 means that somthing auth pass */
			result = SK_RESULT_SUCCESS;
			goto send_result;
		} else if ( 602 != status && 201 != status) { 
			/* status != 602 means that somthing err */
			sprintf(err_buf, "get status %d", status);
			result = SK_RESULT_FAILED;
			goto send_result;
		}
	}

	if (!radiusd_ext_add_timer(hdl, radiusd_ext_do_auth_timer_cb)) {
		result = SK_RESULT_FAILED;
		goto send_result;
	}

	return;

send_result:
	if ( SK_RESULT_FAILED == result )
		radlog(L_INFO, "[%s] reject from secken auth, because [%s].\n", username, err_buf);

	if ( SK_RESULT_SUCCESS == result )
		radlog(L_INFO, "[%s] accept from secken auth.\n", username);

	radiusd_ext_send_back( result, hdl );

	if ( SK_RESULT_FAILED == result ) {
		ulist_del(hdl, auth_hdl_comp);
		radiusd_ext_del_data( hdl );
	}
	if ( SK_RESULT_SUCCESS == result ) {
		if (g_accept_cache_enable)
			accept_user( hdl );
		else {
			ulist_del(hdl, auth_hdl_comp);
			radiusd_ext_del_data( hdl );
		}
	}

	return;
}

static int is_user_in_auth(char *username)
{
	auth_handle_t hdl;
	auth_handle_t *found;

	strcpy(hdl.username, username);
	found = ulist_find_data(&hdl, auth_hdl_comp);
	if (NULL != found) {
		if (STATE_IN_AUTH == found->state)
			return 1;
	}

	return 0;
}

static int is_user_accepted(char *username)
{
	auth_handle_t hdl;
	auth_handle_t *found;

	strcpy(hdl.username, username);
	found = ulist_find_data(&hdl, auth_hdl_comp);
	if (NULL != found) {
		if (STATE_ACCEPTED == found->state && 
			found->retry_count < g_accept_cache_retry) {
			radlog(L_INFO, "[%s] is accepted, accept user.\n", found->username);
			fr_event_delete(found->el, &found->ev);
			ulist_del(found, auth_hdl_comp);
			radiusd_ext_del_data( found );
			return 1;
		}
	}

	return 0;
}

/* 
 * return  0 -- proc in external 
 * return  1 -- continue 
 * return -1 -- error 
 */
int radiusd_ext_do_auth(REQUEST *request, rad_listen_send_t send, fr_event_list_t *el)
{
	auth_handle_t *hdl;
	char event_id[64];
	char err_buf[2048];

	if (request->reply->code != PW_AUTHENTICATION_ACK)
		return 1;

	memset(err_buf, 0, sizeof(err_buf));
	memset(event_id, 0, sizeof(event_id));

	if (is_user_in_auth(request->username->data.strvalue)) {
		radlog(L_INFO, "[%s] already auth in secken process, dorp the request.\n", request->username->data.strvalue);
		return 0;
	}

	if (is_user_accepted(request->username->data.strvalue)) {
		radlog(L_INFO, "[%s] already accept from secken process.\n", request->username->data.strvalue);
		return 1;
	}

	radlog(L_INFO, "[%s] quary secken auth.\n", request->username->data.strvalue);

	if (0 != secken_auth_req(g_auth_url, g_power_id, g_power_key, 
				request->username->data.strvalue, event_id)) {
		strcpy(err_buf, "send secken auth request failed");
		goto auth_err;
	}
	/* if event_id len < 8, the event_id should be an err status */
	if ( 8 > strlen(event_id)) {
		if ( 0 >= strlen(event_id))
			strcpy(err_buf, "recv err secken auth response");
		else
			sprintf(err_buf, "status %s", event_id);
		goto auth_err;
	}

	/* set timer to quary the auth result */
	hdl = radiusd_ext_create_data( el, request, event_id );
	if (NULL == hdl) {
		strcpy(err_buf, "create secken data error");
		goto auth_err;
	}

	/* add user hdl to auth list */
	ulist_add(hdl, auth_hdl_comp);

	if (!radiusd_ext_add_timer( hdl, radiusd_ext_do_auth_timer_cb )) {
		ulist_del(hdl, auth_hdl_comp);
		radiusd_ext_del_data( hdl );
		strcpy(err_buf, "create secken event result timer err");
		goto auth_err;
	}


	return 0;

auth_err:
	radlog(L_ERR, "[%s] can not auth in secken, because [%s].\n", 
			request->username->data.strvalue, err_buf);

	radiusd_send_back(SK_RESULT_FAILED, request->reply, 
			request->packet, request->client->secret);
	return 0;
}

static int radiusd_ext_config_init(char *conf_file)
{
	int ret;
	struct ccl_t conf;
	const char *val;

	conf.comment_char = '#';
	conf.sep_char = '=';
	conf.str_char = '"';

	ret = ccl_parse(&conf, conf_file);
	if (0 != ret) {
		fprintf(stderr, "prase %s error.\n", conf_file);
		return -1;
	}

	val = ccl_get(&conf, "timeout");
	if (!val || !is_digit_str(val)) {
		fprintf(stderr, "option timeout err in %s.\n", conf_file);
		return -1;
	}
	sscanf(val, "%d", &g_timeout);

	val = ccl_get(&conf, "result_req_interval");
	if (!val || !is_digit_str(val))  {
		fprintf(stderr, "option result_req_interval err in %s.\n", conf_file);
		return -1;
	}
	sscanf(val, "%d", &g_result_interval);

	val = ccl_get(&conf, "auth_req_url");
	if (!val || strlen(val) > sizeof(g_auth_url)) {
		fprintf(stderr, "option auth_req_url error in %s.\n", conf_file);
		return -1;
	}
	strcpy(g_auth_url, val);

	val = ccl_get(&conf, "result_req_url");
	if (!val || strlen(val) > sizeof(g_result_url)) {
		fprintf(stderr, "option result_req_url error in %s.\n", conf_file);
		return -1;
	}
	strcpy(g_result_url, val);

	val = ccl_get(&conf, "power_id");
	if (!val || strlen(val) > sizeof(g_power_id)) {
		fprintf(stderr, "option power_id error in %s.\n", conf_file);
		return -1;
	}	
	strcpy(g_power_id, val);

	val = ccl_get(&conf, "power_key");
	if (!val || strlen(val) > sizeof(g_power_key)) {
		fprintf(stderr, "option power_key error in %s.\n", conf_file);
		return -1;
	}
	strcpy(g_power_key, val);

	val = ccl_get(&conf, "accept_cache_enable");
	if (!val) {
		fprintf(stderr, "option accept_cache_enable error in %s.\n", conf_file);
		return -1;
	}
	if (strcpy(val, "yse"))
		g_accept_cache_enable = 1;		
	else if (strcpy(val, "no"))
		g_accept_cache_enable = 0;		
	else {
		fprintf(stderr, "option accept_cache_enable error in %s.\n", conf_file);
		return -1;
	}

	if (g_accept_cache_enable) {
		val = ccl_get(&conf, "accept_cache_time");
		if (!val || !is_digit_str(val)) {
			fprintf(stderr, "option accept_cache_time error in %s.\n", conf_file);
			return -1;
		}
		sscanf(val, "%d", &g_accept_cache_time);

		val = ccl_get(&conf, "accept_cache_retry");
		if (!val || !is_digit_str(val)) {
			fprintf(stderr, "option accept_cache_retry error in %s.\n", conf_file);
			return -1;
		}
		sscanf(val, "%d", &g_accept_cache_retry);
	}

	radlog(L_INFO, "\n---------parse secken config--------\n");
	radlog(L_INFO, "%s\n", conf_file);
	radlog(L_INFO, "timeout = %d\n", g_timeout);
	radlog(L_INFO, "result_req_interval = %d\n", g_result_interval);
	radlog(L_INFO, "auth_req_url = %s\n", g_auth_url);
	radlog(L_INFO, "result_req_url = %s\n", g_result_url);
	radlog(L_INFO, "power_id = %s\n", g_power_id);
	radlog(L_INFO, "power_key = %s\n", g_power_key);
	radlog(L_INFO, "accept_cache_enable = %s\n", g_accept_cache_enable ? "yes" : "no");
	if (g_accept_cache_enable) {
		radlog(L_INFO, "accept_cache_time = %d\n", g_accept_cache_time);
		radlog(L_INFO, "accept_retry = %d\n", g_accept_cache_retry);
	}
	radlog(L_INFO, "\n------------------------------------\n");

	return 0;
}

int radiusd_ext_init(char *conf_file)
{	
	ulist_init();
	return radiusd_ext_config_init(conf_file);
}

