/*
 * ids_io_ctrl.c
 *
 *  Created on: 26/10/2018
 *      Author: mfletche
 */

#include "io_task.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>

#include <assert.h>
#include <errno.h>

#define DEBUG 1
#define DPRINT(...) do {if (DEBUG) fprintf(stdout, __VA_ARGS__);} while(0)

/* TODO: Add support for poll if fd size is too large */

/* Linked list of tasks. */
struct io_task
{
	int fd;	/* the file descriptor */
	TASK_STRUCT task_state;	/* state of the task */

	/* functions to perform read/write tasks */
	ids_io_read on_read;
	ids_io_write on_write;
	ids_io_free on_free;
	struct io_task *next;
};

/* Contains the fd_sets for a list of io_tasks. This is so that constructing
 * all three lists requires one iteration through the list. */
struct io_task_fdsets
{
	fd_set read_fdset;
	fd_set write_fdset;
	fd_set except_fdset;
};

/* These should not be changed after creating an io_task and adding to the list
 * so they are not available to users */
static inline int
io_task_set_fd(struct io_task *task, int fd);

static inline void
io_task_set_on_free(struct io_task *task, ids_io_free on_free);

static inline void
io_task_set_on_read(struct io_task *task, ids_io_read on_read);

static inline void
io_task_set_on_write(struct io_task *task, ids_io_write on_write);

static inline void
io_task_set_task(struct io_task *task, TASK_STRUCT task_state);

/* free a list of ids_io_tasks */
void
free_io_task(struct io_task **task)
{
	assert(task);

	struct io_task *task_iter = *task;
	while (task_iter)
	{
		/* iterate through the list */
		struct io_task *temp = task_iter;
		task_iter = task_iter->next;
		if (temp->on_free) temp->on_free(&(temp->task_state));
		free(temp);
	}

	*task = NULL;
}

void
free_io_task_fdsets(struct io_task_fdsets **fdsets)
{
	assert(fdsets);
	if (*fdsets) free(*fdsets);
	*fdsets = NULL;
}

int
io_task_add(struct io_task **list, struct io_task *task)
{
	assert(list);
	assert(task);

	/* check for duplicates */
	if (io_task_contains(*list, task->fd))
	{
		DPRINT("add_ids_io_task: list already contains task with fd=%d\n", task->fd);
		goto error;
	}

	/* case when list is empty */
	if (!(*list)) *list = task;
	else
	{
		struct io_task *iter = *list;
		while (iter->next) iter = iter->next;
		iter->next = task;
	}

	return (1);

error:
	free_io_task(&task);
	return (0);
}

/*
 * Finds the ids_io_task with the given fd if the list contains it.
 */
struct io_task *
io_task_contains(struct io_task *first, int fd)
{
	/* list could be empty so FIRST can be NULL */

	/* searching for a negative fd will just not find anything, it is
	 * safe to search for it because the list will not be changed */

	struct io_task *found = NULL;
	while (first)
	{
		if (first->fd == fd)
		{
			found = first;
			break;
		}

		first = first->next;
	}

	return (found);
}

/* This function frees the io_task_fdsets structure */
void
io_task_do_io(struct io_task *task, struct io_task_fdsets *fdsets)
{
	if (fdsets)
	{
		while (task)
		{
			if (task->on_read && FD_ISSET(task->fd, &(fdsets->read_fdset))) task->on_read(task->task_state);
			if (task->on_write && FD_ISSET(task->fd, &(fdsets->write_fdset))) task->on_write(task->task_state);

			/*if (FD_ISSET(task->fd, &(fdsets->except_fdset)))
			{
				DPRINT("An exceptional condition occurred for fd: %d\n", task->fd);
			}*/
			task = task->next;
		}
	}
}

void
io_task_get_fdsets(struct io_task *task, struct io_task_fdsets *fdsets)
{
	assert(fdsets);
	if (fdsets)
	{
		/* Reset fdsets */
		FD_ZERO(&(fdsets->read_fdset));
		FD_ZERO(&(fdsets->write_fdset));
		while (task)
		{
			/* Add to read/write set if there is a function to handle that
			 * operation */
			if (task->on_read) FD_SET(task->fd, &(fdsets->read_fdset));
			if (task->on_write) FD_SET(task->fd, &(fdsets->write_fdset));

			/*FD_SET(task->fd, &(fdsets->except_fdset));*/

			task = task->next;
		}
	}

	return;
}

/* Get the maximum file descriptor in the task list. Return -1 if the list is
 * empty. */
int
io_task_max_fd(struct io_task *task)
{
	/* task may be NULL if list is empty */

	int max_fd = -1;
	while (task)
	{
		if (task->fd > max_fd) max_fd = task->fd;
		task = task->next;
	}

	return (max_fd);
}

/* TODO: Should error condition cause something different to happen? */
void
io_task_select(struct io_task *task, struct io_task_fdsets *fdsets)
{
	int max_fd = -1, select_result;
	struct timeval tv;

	/* task may be NULL if list is empty */
	if (task)
	{
		max_fd = io_task_max_fd(task);
		assert(max_fd >= 0);

		/* construct fdsets */
		io_task_get_fdsets(task, fdsets);

		/* do not wait for select */
		tv.tv_sec = 0;
		tv.tv_usec = 0;

		select_result = select(max_fd + 1, &(fdsets->read_fdset),
				&(fdsets->write_fdset), &(fdsets->except_fdset), &tv);

		if (-1 == select_result)
		{
			DPRINT("io_task_select() failed: %s\n", strerror(errno));
			assert(EBADF != errno);
			assert(EINVAL != errno);

			/* Errors which can occur without programmer error are EINTR and
			 * ENOMEM */
			goto error;
		}
		else if (select_result)
		{
			/* DPRINT("io_task_select() has IO tasks ready\n"); */
		}
		else
		{
			free_io_task_fdsets(&fdsets);
		}

		return;
	}

error:
	free_io_task_fdsets(&fdsets);
	return;
}

/* Setters for io_task fields */

static inline int
io_task_set_fd(struct io_task *task, int fd)
{
	assert(task);

	/* negative integers indicate error conditions */
	assert(fd >= 0 && fd < FD_SETSIZE);

	if (fd >= FD_SETSIZE)
	{
		DPRINT("io_task_set_fd(): File descriptor too large to monitor with select(): %d\n", fd);
		return (0);
	}

	if (fd < 0)
	{
		DPRINT("io_task_set_fd(): File descriptor invalid: %d\n", fd);
		return (0);
	}

	task->fd = fd;
	return (1);
}

static inline void
io_task_set_on_free(struct io_task *task, ids_io_free on_free)
{
	assert(task);

	if (task) task->on_free = on_free;
}

static inline void
io_task_set_on_read(struct io_task *task, ids_io_read on_read)
{
	assert(task);

	/* on_read may be NULL */

	if (task) task->on_read = on_read;
}

static inline void
io_task_set_on_write(struct io_task *task, ids_io_write on_write)
{
	assert(task);

	/* on_write may be NULL */

	if (task) task->on_write = on_write;
}

static inline void
io_task_set_task(struct io_task *task, TASK_STRUCT task_state)
{
	assert(task);
	assert(task_state);

	/* task_state may not be NULL */

	if (task) task->task_state = task_state;
}

/* Get a point to a new zeroed ids_io_task structure or NULL if memory
 * allocation failed. */
struct io_task *
new_io_task(int fd, TASK_STRUCT task_state, ids_io_read do_read, ids_io_write do_write,
		ids_io_free do_free)
{
	/* At least one of read or write must be non-NULL */
	assert(do_read || do_write);

	struct io_task *task = malloc(sizeof(*task));
	if (task)
	{
		if (!io_task_set_fd(task, fd)) goto error;
		io_task_set_task(task, task_state);
		io_task_set_on_read(task, do_read);
		io_task_set_on_write(task, do_write);
		io_task_set_on_free(task, do_free);
		task->next = NULL;
	}
	return (task);

error:
	free_io_task(&task);
	return (task);
}

struct io_task_fdsets *
new_io_task_fdsets()
{
	struct io_task_fdsets *fdsets = malloc(sizeof(*fdsets));
	if (fdsets)
	{
		FD_ZERO(&(fdsets->read_fdset));
		FD_ZERO(&(fdsets->write_fdset));
		FD_ZERO(&(fdsets->except_fdset));
	}
	return (fdsets);
}
