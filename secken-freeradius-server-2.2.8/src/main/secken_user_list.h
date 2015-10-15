#ifndef __SECKEN_USER_LIST_H__
#define __SECKEN_USER_LIST_H__

typedef int (*comp_fn)(void *src, void *dst);

void *ulist_find_data(void *hdl, comp_fn comp);
int ulist_is_user_exist(void *hdl, comp_fn comp);
int ulist_add(void *hdl, comp_fn comp);
int ulist_del(void *hdl, comp_fn comp);

#endif
