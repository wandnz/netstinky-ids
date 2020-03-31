/*
 * linked_list.h
 *
 *  Created on: 26/10/2018
 *      Author: mfletche
 *
 * An empty list is represented by a NULL pointer to a linked_list.
 *
 * Each item is a pointer. It is assumed that all items in the list are of the
 * same type, as there is no way of distinguishing between them.
 */

#ifndef LINKED_LIST_H_
#define LINKED_LIST_H_

typedef void *LINKED_LIST_ITEM;

typedef void (*free_linked_list_item)(LINKED_LIST_ITEM);

struct linked_list
{
    LINKED_LIST_ITEM item;
    struct linked_list *next;
};

void
free_linked_list(struct linked_list **list, free_linked_list_item free_item);

int
linked_list_add_item(struct linked_list **list, LINKED_LIST_ITEM item);

struct linked_list *
linked_list_get_last_item(struct linked_list *list);

/**
 * Gets the first item in the linked list, and removes it from the list.
 */
LINKED_LIST_ITEM
linked_list_pop(struct linked_list **list);

struct linked_list *
new_linked_list(LINKED_LIST_ITEM item);

#endif /* LINKED_LIST_H_ */
