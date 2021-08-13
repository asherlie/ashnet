#include <pthread.h>

#include "packet.h"

/* used to queue messages up for broadcast */
struct mq_entry{
    struct mq_entry* next;
    struct new_beacon_packet* packet;
};

struct mqueue{
    struct mq_entry* first, * last;
    pthread_mutex_t lock;
};

void init_mqueue(struct mqueue* mq);
