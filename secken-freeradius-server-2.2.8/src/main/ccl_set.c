/*
 *  Copyright (C) 2012 Stephen F. Booth
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h> 	/* malloc, free */
#include <string.h>

#include "ccl.h"

struct ccl_pair_t* ccl_set(const struct ccl_t *data, 
		const char *key, const char *value)
{
  struct ccl_pair_t *pair;

  if(data == 0 || key == 0 || value == 0)
    return 0;

  pair = (struct ccl_pair_t*) malloc(sizeof(struct ccl_pair_t));
  pair->key = strdup((char*) key);
  pair->value = strdup((char*) value);

  return (struct ccl_pair_t*) bst_replace(data->table, pair);
}
