/**
 * A queue of recent events which have been detected by the IDS. The queue
 * maintains a maximum number of events which is set at initialization
 *
 * The events contain information about where they originated, on what
 * interface they were detected, indicator of compromise and time.
 */

#include <stdint.h>

#include "linked_list.h"

struct ids_event;
struct ids_event_time;
struct ids_event_list;

/**
 * Free an ids_event structure and any further entries in the list.
 * @param e A pointer to the address of the first ids_event to free. May not be
 * NULL but can handle (*e) being NULL.
 */
void
free_ids_event(struct ids_event **e);

void
free_ids_event_list(struct ids_event_list **list);

/**
 * Free an ids_event_time structure and any further entries in the list.
 * @param t A pointer to the address of the first ids_event_time to free. May
 * not be NULL but can handle *T being NULL.
 */
void
free_ids_event_time(struct ids_event_time **t);

/**
 * Add an event to the front of the list. If E is added to the list it will be
 * cleaned up by a single call to free_ids_event on the head of the list.
 * Otherwise the caller is responsible for freeing E.
 * @param list Pointer to an ids_event_list struct. May not be NULL.
 * @param e The event to add to the list.
 * @return 1 if the event was added to the list, 0 if unsuccessful.
 */
int
ids_event_list_add(struct ids_event_list *list, struct ids_event *e);

/**
 * Checks if the ids_event list contains an event equivalent to E, and returns
 * the equivalent event if it was found.
 *
 * If an event is found, E should not be a new entry in the event list, but
 * should have its timestamp added to the list of ids_event_time associated
 * with the equivalent event.
 *
 * @param list The ids_event_list to search.
 * @param e The event to search for.
 * @return The address of an equivalent event.
 */
struct ids_event *
ids_event_list_contains(struct ids_event_list *list, struct ids_event *e);

void
ids_event_list_remove_old_events(struct ids_event_list *list);

/**
 * Add a timestamp to the front of a list of times.
 * @param list The address of a pointer to the head of the list. May not be
 * NULL but *list may be NULL.
 * @param tm The timestamp to add to the list.
 * @return 1 if successful, 0 if unsuccessful.
 */
int
ids_event_time_list_add(struct ids_event_time **list, struct ids_event_time *tm);

/**
 * Creates a new IDS event with the attributes provided and a current
 * timestamp.
 * @param iface The name of the network interface which observed this event.
 * May not be NULL.
 * @param src_ip The IP of the device which generated this event.
 * @param ioc A string containing the indicator of compromise (a domain name or
 * a string-ified IP address). May not be NULL.
 * @return A pointer to a valid ids_event structure, or NULL if the ids_event
 * could not be created.
 */
struct ids_event *
new_ids_event(char *iface, uint32_t src_ip, char *ioc);

/**
 * Creates a new IDS event list with the given number of maximum events and
 * maximum timestamps. The least recent events and timestamps will be dropped
 * if the maximums would be exceeded.
 * @param max_events The maximum length of the list of events.
 * @param max_timestamps The maximum length of the list of timestamps in each
 * event.
 * @return A valid ids_event_list or NULL if the ids_event_list could not be
 * created.
 */
struct ids_event_list *
new_ids_event_list(unsigned int max_events, unsigned int max_timestamps);

/**
 * Gets a new ids_event_time struct which can be added to an ids_event.
 * @return A valid ids_event_time struct for the current time, or NULL if the
 * ids_event_time could not be created.
 */
struct ids_event_time *
new_ids_event_time();
