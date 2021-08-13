#include <stdlib.h>
#include <string.h>

#include "mq.h"

void init_mqueue(struct mqueue* mq){
    pthread_mutex_init(&mq->lock, NULL);
    mq->first = mq->last = NULL;
}

void insert_mqueue(struct mqueue* mq, struct new_beacon_packet* nbp){
    struct mq_entry* e = malloc(sizeof(struct mq_entry));
    e->next = NULL;
    /*memcpy(e->msg, msg, 32);*/

    /* for now, we're not using the same pointer */
    /* TODO: should i use nbp instead of copying its contents? */
    memcpy(&e->packet, nbp, sizeof(struct new_beacon_packet));

    pthread_mutex_lock(&mq->lock);
    if(!mq->first){
        mq->first = mq->last = e;
    }
    else{
        mq->last->next = e;
        mq->last = e;
    }
    pthread_mutex_unlock(&mq->lock);
}

int main(){
}
