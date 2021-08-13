#include <pthread.h>

#include "packet.h"

/* used to queue messages up for broadcast */
struct mq_entry{
    struct mq_entry* next;
    struct new_beacon_packet* packet;
    /* if this is set, the broadcast thread will overwrite 
     * the BSSID and mac address fields with local addr
     *
     * this may be unwanted behavior at times - for example,
     * when spreading a message that did not originate at
     * a given node
     */
    _Bool overwrite_addr;
    _Bool free_mem;
};

struct mqueue{
    struct mq_entry* first, * last;
    pthread_mutex_t lock;
    pthread_cond_t nonempty;
};

void init_mqueue(struct mqueue* mq);
/* if overwrite_addr is not set, nbp's address fields should have already been set */
//void insert_mqueue(struct mqueue* mq, struct new_beacon_packet* nbp, _Bool overwrite_addr);
void insert_mqueue(struct mqueue* mq, struct new_beacon_packet* nbp, _Bool overwrite_addr, _Bool free_mem);
//struct new_beacon_packet* pop_mqueue_blocking(struct mqueue* mq);
struct mq_entry* pop_mqueue_blocking(struct mqueue* mq);
