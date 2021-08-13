#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "mq.h"

void init_mqueue(struct mqueue* mq){
    pthread_mutex_init(&mq->lock, NULL);
    pthread_cond_init(&mq->nonempty, NULL);
    mq->first = mq->last = NULL;
}

/*void insert_mqueue(struct mqueue* mq, struct new_beacon_packet* nbp){*/
void insert_mqueue(struct mqueue* mq, struct new_beacon_packet* nbp, _Bool overwrite_addr){
    struct mq_entry* e = malloc(sizeof(struct mq_entry));
    e->next = NULL;
    e->packet = nbp;
    e->overwrite_addr = overwrite_addr;

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
/*struct new_beacon_packet* pop_mqueue_blocking(struct mqueue* mq){*/
struct mq_entry* pop_mqueue_blocking(struct mqueue* mq){
    pthread_mutex_t tmp_lck;
    /*struct new_beacon_packet* ret = NULL;*/
    struct mq_entry* ret = NULL;

    pthread_mutex_init(&tmp_lck, NULL);

    while(!ret){
        pthread_mutex_lock(&tmp_lck);
        /*
         * oops, this shouldn't be called in case of nonempty, we'll just wait in this case
         * for no reason until the next insertion
         * we really should lcok on the big one first
        */
        pthread_mutex_lock(&mq->lock);
        /*if(!mq->first)pthread_cond_wait(&mq->nonempty, &tmp_lck);*/
        if(mq->first){
            ret = mq->first;
            /*printf("ret!: %p\n", ret);*/
            mq->first = mq->first->next;
            pthread_mutex_unlock(&mq->lock);
            break;
        }
        pthread_mutex_unlock(&mq->lock);
        pthread_cond_wait(&mq->nonempty, &tmp_lck);

        #if 0
        /* we don't need to check for emptiness */
        pthread_mutex_lock(&mq->lock);
        ret = mq->first->packet;
        if(ret)mq->first = mq->first->next;
        pthread_mutex_unlock(&mq->lock);
        #endif
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
    insert_mqueue(&mq, nbp, 0);
    insert_mqueue(&mq, nbp, 0);
    insert_mqueue(&mq, nbp, 0);
    insert_mqueue(&mq, nbp, 0);

    struct mq_entry* me;
    while((me = pop_mqueue_blocking(&mq))){
        printf("%p == %p\n", me->packet, nbp);
    }
    /*
     * while((ret = pop_mqueue(&mq))){
     *     printf("%p == %p\n", ret, nbp);
     * }
    */

}
#endif
