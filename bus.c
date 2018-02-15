#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "bus.h"

#define BUS_MAX_CLIENTS 64
#define BUS_MAX_MESSAGES 256

enum client_state {
    BUS_CLIENT_CONNECTED = 0x01,
    BUS_CLIENT_DIRTY = 0xFE,
    BUS_CLIENT_FREE = 0xFF,
};

enum message_state {
    BUS_MSG_DIRTY = 0xFE,
    BUS_MSG_FREE = 0xFF,
};

typedef uint64_t message_id_t;
#define MAX_MESSAGE_ID UINT64_MAX

struct bus {
    uint8_t clients_table[BUS_MAX_CLIENTS];
    /* The sequence counter associated with each bus client (to be sure
     * that messages are delivered in order). */
    message_id_t next_message_id_for_client[BUS_MAX_CLIENTS];
    uint8_t message_table[BUS_MAX_MESSAGES];
    message_id_t message_id_table[BUS_MAX_MESSAGES];
    char clients[BUS_MAX_CLIENTS][BUS_MAX_CLIENT_NAME];
    uint8_t messages[BUS_MAX_MESSAGES][BUS_MAX_MESSAGE_SIZE];
};

struct bus_connection {
    const char *client_name;
    int client_id;
    /* Next message ID for this client to be fetched from bus */
    message_id_t message_id_to_fetch;
    struct bus *bus;
};

static inline bool atomic_compare_and_swap(uint8_t *ptr, uint8_t expected,
    uint8_t desired)
{
    return __atomic_compare_exchange_n(ptr, &expected, desired, false,
        __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

static inline message_id_t atomic_fetch_and_inc(message_id_t *ptr)
{
    return __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST);
}

int bus_create(const char *bus_name)
{
    /* TODO: prepend "/" to bus_name */

    int shmfd = shm_open(bus_name, O_RDWR | O_CREAT | O_EXCL, 0666);
    if (shmfd == -1) {
        return -1;
    }

    if (ftruncate(shmfd, sizeof(struct bus)) == -1) {
        return -1;
    }

    struct bus *bus = mmap(NULL, sizeof(struct bus), PROT_READ | PROT_WRITE,
        MAP_SHARED, shmfd, 0);
    close(shmfd);
    if (bus == MAP_FAILED) {
        shm_unlink(bus_name);
        return -1;
    }

    memset(bus, -1, sizeof(struct bus));
    memset(bus->next_message_id_for_client, 0, sizeof(bus->next_message_id_for_client));
    memset(bus->message_id_table, 0, sizeof(bus->message_id_table));

    return 0;
}

void bus_destroy(const char *bus_name)
{
    shm_unlink(bus_name);
}

BusConnection *bus_connect(const char *bus_name, const char *client_name)
{
    int shmfd = shm_open(bus_name, O_RDWR, 0666);
    if (shmfd == -1) {
        return NULL;
    }

    struct bus *bus = mmap(NULL, sizeof(struct bus), PROT_READ | PROT_WRITE,
        MAP_SHARED, shmfd, 0);
    close(shmfd);
    if (bus == MAP_FAILED) {
        return NULL;
    }

    int client_id = 0;
    bool registration_completed = false;

    for (client_id = 0; client_id < BUS_MAX_CLIENTS; ++client_id) {
        if (bus->clients_table[client_id] != BUS_CLIENT_CONNECTED) {
            continue;
        }
        if (strncmp(bus->clients[client_id], client_name, BUS_MAX_CLIENT_NAME) == 0) {
            registration_completed = true;
            break;
        }
    }

    if (!registration_completed) {
        for (client_id = 0; client_id < BUS_MAX_CLIENTS; ++client_id) {
            if (bus->clients_table[client_id] != BUS_CLIENT_FREE) {
                continue;
            }

            bool free_place_found = atomic_compare_and_swap(
                &bus->clients_table[client_id],
                BUS_CLIENT_FREE, BUS_CLIENT_DIRTY);

            if (!free_place_found) {
                continue;
            }

            strncpy(bus->clients[client_id], client_name, BUS_MAX_CLIENT_NAME);
            registration_completed = true;
            break;
        }
    }

    if (!registration_completed) {
        return NULL;
    }

    BusConnection *bc = malloc(sizeof(BusConnection));
    if (bc == NULL) {
        bus->clients_table[client_id] = BUS_CLIENT_FREE;
        return NULL;
    }

    bc->bus = bus;
    bc->client_id = client_id;
    bc->client_name = strdup(client_name);
    if (bc->client_name == NULL) {
        free(bc);
        bus->clients_table[client_id] = BUS_CLIENT_FREE;
        return NULL;
    }

    message_id_t message_id_to_fetch = bus->next_message_id_for_client[client_id];

    /* Assuming that there was some messages delivered while client was offline,
     * search for smallest message ID for this client ID.
     *
     * FIXME: There is an issue that may cause messages order to be broken
     * on message_id overflow: assume that client is disconnected, and while
     * being offline, received message with maximum possible ID and then with
     * minimum possible ID (0). In this case smallest found ID will be zero,
     * and message with maximum possible ID will be lost (indeed case is a bit
     * wider, but the main idea is clear). */
    bool unreceived_messages = false;
    message_id_t min_message_id = MAX_MESSAGE_ID;
    for (int msg_index = 0; msg_index < BUS_MAX_MESSAGES; ++msg_index) {
        if (bus->message_table[msg_index] == client_id) {
            if (bus->message_id_table[msg_index] < min_message_id) {
                min_message_id = bus->message_id_table[msg_index];
            }
            unreceived_messages = true;
        }
    }
    if (unreceived_messages) {
        bc->message_id_to_fetch = min_message_id;
    } else {
        bc->message_id_to_fetch = message_id_to_fetch;
    }

    bus->clients_table[client_id] = BUS_CLIENT_CONNECTED;

    return bc;
}

int bus_get_client_id(BusConnection *bc, const char *client_name)
{
    assert(bc != NULL);
    assert(client_name != NULL);

    struct bus *bus = bc->bus;

    for (int client_id = 0; client_id < BUS_MAX_CLIENTS; ++client_id) {
        if (bus->clients_table[client_id] != BUS_CLIENT_CONNECTED) {
            continue;
        }
        if (strncmp(bus->clients[client_id], client_name, BUS_MAX_CLIENT_NAME) == 0) {
            return client_id;
        }
    }

    return -1;
}

int bus_post_message(BusConnection *bc, int client_id, void *msg, size_t len)
{
    struct bus *bus = bc->bus;

    for (int msg_index = 0; msg_index < BUS_MAX_MESSAGES; ++msg_index) {
        if (bus->message_table[msg_index] != BUS_MSG_FREE) {
            continue;
        }

        bool message_acquired = atomic_compare_and_swap(
            &bus->message_table[msg_index],
            BUS_MSG_FREE, BUS_MSG_DIRTY);

        if (!message_acquired) {
            continue;
        }

        memcpy(bus->messages[msg_index], msg, len);
        message_id_t message_id = atomic_fetch_and_inc(
            &bus->next_message_id_for_client[client_id]);
        bus->message_id_table[msg_index] = message_id;
        bus->message_table[msg_index] = (uint8_t)client_id;
        return 0;
    }

    return -1;
}

int bus_fetch_message(BusConnection *bc, void *msg, size_t len)
{
    struct bus *bus = bc->bus;

    /* There is no messages to fetch if next message id to fetch is the same
     * as next message id */
    if (bc->message_id_to_fetch == bus->next_message_id_for_client[bc->client_id]) {
        return -1;
    }

    for (int msg_index = 0; msg_index < BUS_MAX_MESSAGES; ++msg_index) {
        if (bus->message_table[msg_index] != bc->client_id) {
            continue;
        }

        if (bus->message_id_table[msg_index] != bc->message_id_to_fetch) {
            continue;
        }

        memcpy(msg, bus->messages[msg_index], len);
        bc->message_id_to_fetch++;
        bus->message_table[msg_index] = BUS_MSG_FREE;
        return 0;
    }

    /* There is may be an issue when message with current ID to fetch not found,
     * but there are other messages for this client exists. This may happen if
     * posting of message on some client was interrupted and that client stopped
     * working just between incrementing message ID and writing client ID
     * to message_table. */

    return -1;
}

void bus_flush_messages(BusConnection *bc)
{
    struct bus *bus = bc->bus;

    for (int msg_index = 0; msg_index < BUS_MAX_MESSAGES; ++msg_index) {
        if (bus->message_table[msg_index] != bc->client_id) {
            continue;
        }

        bus->message_table[msg_index] = BUS_MSG_FREE;
    }
}
