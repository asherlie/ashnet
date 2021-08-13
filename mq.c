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
    e->packet = nbp;

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

struct new_beacon_packet* pop_mqueue(struct mqueue* mq){
    struct new_beacon_packet* ret;
    pthread_mutex_lock(&mq->lock);
    ret = mq->first;
    if(ret)mq->first = mq->first->next;
    pthread_mutex_unlock(&mq->lock);
    return ret;
}

int main(){
}
