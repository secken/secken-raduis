#ifndef __EXTERNAL_H__
#define __EXTERNAL_H__

int radiusd_ext_do_auth(
		REQUEST *request, 
		rad_listen_send_t send, 
		fr_event_list_t *el);


#endif
