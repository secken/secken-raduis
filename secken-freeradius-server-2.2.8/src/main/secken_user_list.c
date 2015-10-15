#include <stdio.h>
#include <stdlib.h>

#include "list.h"
#include "secken_user_list.h"

struct list_head g_auth_list;

typedef struct _secken_ulist {
	struct list_head list;
	void *hdl;
} secken_ulist; 


static secken_ulist *ulist_find_ulist(void *hdl, comp_fn comp) 
{
	secken_ulist *ulist = NULL;

	list_for_each_entry(ulist, &g_auth_list, list) {
		if (NULL != ulist) 
			if (1 == comp(hdl, ulist->hdl))
				return ulist;
	}

	return NULL;
}

void ulist_init(void)
{
	INIT_LIST_HEAD(&g_auth_list);
}

void *ulist_find_data(void *hdl, comp_fn comp)
{
	secken_ulist *ulist = NULL;

	list_for_each_entry(ulist, &g_auth_list, list) {
		if (NULL != ulist) 
			if (1 == comp(hdl, ulist->hdl))
				return ulist->hdl;
	}

	return NULL;
}

int ulist_add(void *hdl, comp_fn comp)
{
	secken_ulist *ulist;

	ulist = (secken_ulist *)malloc(sizeof(secken_ulist));
	if (NULL == ulist)
		return -1;

	INIT_LIST_HEAD(&ulist->list);
	ulist->hdl = hdl;

	list_add_tail(&g_auth_list, &ulist->list);

	return 0;
}

int ulist_del(void *hdl, comp_fn comp)
{
	secken_ulist *ulist = NULL;

	ulist = ulist_find_ulist(hdl, comp);
	if (NULL == ulist)
		return -1;

	list_del(&ulist->list);
	free(ulist);

	return 0;
}
