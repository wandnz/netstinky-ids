/*
 * linked_list.c
 *
 *  Created on: 26/10/2018
 *      Author: mfletche
 */

#include <stdlib.h>
#include <assert.h>
#include "linked_list.h"

/*
 * This function asks for a pointer-pointer as it will change the pointer to
 * NULL for tidiness. free_item may be NULL.
 */
void
free_linked_list(struct linked_list **list, free_linked_list_item free_item)
{
	assert(list);

	struct linked_list *temp = NULL;

	if (list)
	{
		while (*list)
		{
			if (free_item) free_item((*list)->item);
			temp = *list;

			/* The linked_list pointer will be set to NULL by this eventually */
			*list = (*list)->next;
			free(temp);
		}
	}
}

int
linked_list_add_item(struct linked_list **list, LINKED_LIST_ITEM item)
{
	assert(list);
	assert(item);

	struct linked_list *new_item = NULL;
	int success = 0;

	if (list && item)
	{
		new_item = new_linked_list(item);
		if (new_item)
		{
			struct linked_list *last = linked_list_get_last_item(*list);
			if (last) last->next = new_item;

			/* case when there are no items in list */
			else *list = new_item;

			success = 1;
		}
	}

	return (success);
}

struct linked_list *
linked_list_get_last_item(struct linked_list *list)
{
	/* NULL is acceptable input as it represents an empty list */

	struct linked_list *result = NULL;

	while (list)
	{
		result = list;
		list = list->next;
	}

	return (result);
}

struct linked_list *
new_linked_list(LINKED_LIST_ITEM item)
{
	assert(item);

	struct linked_list *list = NULL;

	/* Don't continue if the item is invalid */
	if (item)
	{
		list = malloc(sizeof(*list));
		if (list)
		{
			list->item = item;
			list->next = NULL;
		}
	}

	return (list);
}
