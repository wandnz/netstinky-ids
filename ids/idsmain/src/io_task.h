/*
 * ids_io_ctrl.h
 *
 *  Created on: 26/10/2018
 *      Author: mfletche
 *
 * Acts as a controller/co-ordinator for the many IO tasks which must
 * operate on the IDS. Each of these tasks uses one or more file descriptors
 * which must be read/written only at a time when data is ready so that they
 * will be non-blocking.
 *
 * Each file descriptor is bundled with function pointers which will be called
 * when a read or write operation can be performed. A pointer to a structure
 * which stores the state of the task will be passed to the functions.
 *
 * The tasks will be monitored by select for operations which the task has a
 * function to handle. For example, if on_read is defined the task will be
 * added to the read set. If on_read is NULL it will not be added to the read
 * set.
 */

#ifndef IO_TASK_H_
#define IO_TASK_H_

/* Any information required about the state of the task. This will be passed to
 * the on_read and on_write callbacks. */
typedef void *TASK_STRUCT;

/* Represents tasks that require reading or writing of the file descriptor. */
typedef int (*ids_io_read)(TASK_STRUCT task_state);
typedef int (*ids_io_write)(TASK_STRUCT task_state);
typedef void (*ids_io_free)(TASK_STRUCT *task_state);

/* Linked list of tasks. */
struct io_task;

/* Contains the fd_sets for a list of io_tasks. This is so that constructing
 * all three lists requires one iteration through the list. */
struct io_task_fdsets;

void
free_io_task(struct io_task **task);

void
free_io_task_fdsets(struct io_task_fdsets **fdsets);

int
io_task_add(struct io_task **list, struct io_task *task);

struct io_task *
io_task_contains(struct io_task *first, int fd);

void
io_task_do_io(struct io_task *task, struct io_task_fdsets *fdsets);

struct io_task_fdsets *
io_task_get_fdsets(struct io_task *task);

int
io_task_max_fd(struct io_task *task);

/*
 * Returns a structure containing fd_set fields which indicate which IO tasks
 * can do work without blocking. If there was an error, or there were no
 * non-blocking tasks, returns NULL. */
struct io_task_fdsets *
io_task_select(struct io_task *task);

struct io_task *
new_io_task(int fd, TASK_STRUCT task_state, ids_io_read do_read, ids_io_write do_write,
		ids_io_free do_free);

struct io_task_fdsets *
new_io_task_fdsets();

#endif /* IO_TASK_H_ */
