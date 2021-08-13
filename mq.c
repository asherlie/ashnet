#include <stdlib.h>
#include <string.h>

#include "mq.h"

void init_mqueue(struct mqueue* mq){
    pthread_mutex_init(&mq->lock, NULL);
    pthread_cond_init(&mq->nonempty, NULL);
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
    /* broadcasting while lock acquired */
    pthread_cond_broadcast(&mq->nonempty);

    pthread_mutex_unlock(&mq->lock);
}

struct new_beacon_packet* pop_mqueue(struct mqueue* mq){
    struct new_beacon_packet* ret; 
    pthread_mutex_lock(&mq->lock);
    if(!mq->first){
        ret = NULL;
    }
    else{
        ret = mq->first->packet;
        mq->first = mq->first->next;
    }
    pthread_mutex_unlock(&mq->lock);
    return ret;
}

/*
 * when this is called, if the queue's empty
 * it'll wait on a conditional that is only
 * toggled once an element is inserted
*/
struct new_beacon_packet* pop_mqueue_blocking(struct mqueue* mq){
    pthread_mutex_t tmp_lck;
    struct new_beacon_packet* ret = NULL;

    pthread_mutex_init(&tmp_lck, NULL);

    while(!ret){
        pthread_mutex_lock(&tmp_lck);
        pthread_cond_wait(&mq->nonempty, &tmp_lck);

        /* we don't need to check for emptiness */
        pthread_mutex_lock(&mq->lock);
        ret = mq->first->packet;
        if(ret)mq->first = mq->first->next;
        pthread_mutex_unlock(&mq->lock);
    }

    pthread_mutex_unlock(&tmp_lck);
    pthread_mutex_destroy(&tmp_lck);

    return ret;
}

#if 0
int main(){
    struct mqueue mq;
    init_mqueue(&mq);

    struct new_beacon_packet* nbp = malloc(sizeof(struct new_beacon_packet)), * ret;
    insert_mqueue(&mq, nbp);
    insert_mqueue(&mq, nbp);
    insert_mqueue(&mq, nbp);
    insert_mqueue(&mq, nbp);

    while((ret = pop_mqueue(&mq))){
        printf("%p == %p\n", ret, nbp);
    }

}
#endif
