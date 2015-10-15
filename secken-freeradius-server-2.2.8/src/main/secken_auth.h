#ifndef __SECKEN_AUTH_H__
#define __SECKEN_AUTH_H__

int secken_auth_req(
		char *url, 
		char *power_id, 
		char *power_key, 
		char *username,
		char *event_id);

int secken_event_req(
		char *url, 
		char *power_id, 
		char *power_key, 
		char *event_id,
		int *status);

#endif
