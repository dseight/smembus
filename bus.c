#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
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

typedef struct timespec message_id_t;
static const message_id_t MAX_MESSAGE_ID = {
    .tv_sec = (((time_t) 1 << (sizeof(time_t) * 8 - 2)) - 1) * 2 + 1,
    .tv_nsec = (((long) 1 << (sizeof(long) * 8 - 2)) - 1) * 2 + 1
};


struct bus {
    uint8_t clients_table[BUS_MAX_CLIENTS];
    uint8_t message_table[BUS_MAX_MESSAGES];
    message_id_t message_id_table[BUS_MAX_MESSAGES];
    char clients[BUS_MAX_CLIENTS][BUS_MAX_CLIENT_NAME];
    uint8_t messages[BUS_MAX_MESSAGES][BUS_MAX_MESSAGE_SIZE];
};

struct bus_connection {
    const char *client_name;
    int client_id;
    struct bus *bus;
};

static inline bool atomic_compare_and_swap(uint8_t *ptr, uint8_t expected,
    uint8_t desired)
{
    return __atomic_compare_exchange_n(ptr, &expected, desired, false,
        __ATOMIC_SEQ_CST, __ATOMIC_RELAXED);
}

static bool message_id_is_lower(const message_id_t *id1, const message_id_t *id2)
{
    if (id1->tv_sec == id2->tv_sec) {
        return id1->tv_nsec < id2->tv_nsec;
    } else {
        return id1->tv_sec < id2->tv_sec;
    }
}

static void get_message_id(message_id_t *id)
{
    clock_gettime(CLOCK_MONOTONIC, (struct timespec *)id);
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
        get_message_id(&bus->message_id_table[msg_index]);
        bus->message_table[msg_index] = (uint8_t)client_id;
        return 0;
    }

    return -1;
}

static int lowest_message_index_to_fetch(struct bus *bus, int client_id)
{
    const message_id_t *lowest_msg_id = &MAX_MESSAGE_ID;
    int lowest_index = -1;

    for (int msg_index = 0; msg_index < BUS_MAX_MESSAGES; ++msg_index) {
        if (bus->message_table[msg_index] != client_id) {
            continue;
        }

        const message_id_t *current_msg_id = &bus->message_id_table[msg_index];

        if (message_id_is_lower(current_msg_id, lowest_msg_id)) {
            lowest_msg_id = current_msg_id;
            lowest_index = msg_index;
        }
    }

    return lowest_index;
}

int bus_fetch_message(BusConnection *bc, void *msg, size_t len)
{
    struct bus *bus = bc->bus;

    int msg_index = lowest_message_index_to_fetch(bus, bc->client_id);
    if (msg_index == -1) {
        return -1;
    }

    memcpy(msg, bus->messages[msg_index], len);
    bus->message_table[msg_index] = BUS_MSG_FREE;
    return 0;
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
