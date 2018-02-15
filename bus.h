#ifndef SMEMBUS_H
#define SMEMBUS_H

#include <stddef.h>

#define BUS_MAX_MESSAGE_SIZE 64
#define BUS_MAX_CLIENT_NAME 64

typedef struct bus_connection BusConnection;

/* bus_name always *must* start from "/" ! */

/* Create new bus. It must be created in one process, other processes
 * just connects to bus.
 * Returns 0 on success and -1 on error.
 * If bus with specified name already exists, errno will be set to EEXIST. */
int bus_create(const char *bus_name);

/* Destorys previously created bus.
 * Bus will not be destroyed until exit of every proccess connected to bus.
 * New connections (after bus_destroy(), then bus_create() call) will connect
 * to different bus, even if it has the same name.
 * TODO: better description */
void bus_destroy(const char *bus_name);

/* Connect to bus with specified name.
 * Returns pointer to bus or NULL on error. */
BusConnection *bus_connect(const char *bus_name, const char *client_name);

/* Get ID of some bus client.
 * Returns client ID on success or -1 if there is no client with specified name. */
int bus_get_client_id(BusConnection *bc, const char *client_name);

/* Post new message to bus.
 * Returns 0 on success and non-zero status on error
 * (e.g. there is no available space on bus). */
int bus_post_message(BusConnection *bc, int client_id, void *msg, size_t len);

/* Try to fetch new message from bus.
 * Return value:
 *  0 if message successcully fetched,
 * -1 if no message fetched. */
int bus_fetch_message(BusConnection *bc, void *msg, size_t len);

/* Remove all messages sent for current client */
void bus_flush_messages(BusConnection *bc);

#endif /* SMEMBUS_H */
