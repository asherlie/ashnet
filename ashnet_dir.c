#include "ashnet_dir.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

void init_an_directory(struct an_directory* ad, int storage){
    memset(ad->buckets, 0, sizeof(ad->buckets));
    ad->packet_storage = storage;
    pthread_mutex_init(&ad->lock, NULL);
    memset(ad->viable_packet_len, -1, sizeof(ad->viable_packet_len));
    ad->ignored_packets = 0;
}

int sum_addr(unsigned char* addr){
    int ret = 0;
    for(int i = 0; i < 6; ++i)
        ret += (int)addr[i];
    return ret;
}

struct mac_entry* create_mac_entry(unsigned char* addr, char* uname){
    struct mac_entry* ret = malloc(sizeof(struct mac_entry));
    memcpy(ret->addr, addr, 6);
    memcpy(ret->uname, uname, UNAME_LEN);
    ret->next = NULL;
    return ret;
}

struct mac_entry* insert_uname(struct an_directory* ad, unsigned char* addr, char* uname){
    struct mac_entry* last_me, * ret;
    int idx;
    pthread_mutex_lock(&ad->lock);
    if(!ad->buckets[(idx = sum_addr(addr))]){
        ad->buckets[idx] = create_mac_entry(addr, uname);
        ad->buckets[idx]->nbp = malloc(sizeof(struct new_beacon_packet)*ad->packet_storage);

        /* both == 0 until n_packets == ad->packet_storage, only then does pkt_idx loop around
         * to overwrite the oldest stored values
         */
        ad->buckets[idx]->n_packets = 0;
        ad->buckets[idx]->pkt_idx = 0;
        last_me = ad->buckets[idx];
        pthread_mutex_unlock(&ad->lock);
        return last_me;
    }
    for(struct mac_entry* me = ad->buckets[idx]; me; me = me->next){
        /* in case of updated uname */
        if(!memcmp(me->addr, addr, 6)){
            memcpy(me->uname, uname, UNAME_LEN);
            pthread_mutex_unlock(&ad->lock);
            return me;
        }
        last_me = me;
    }
    ret = last_me->next = create_mac_entry(addr, uname);
    pthread_mutex_unlock(&ad->lock);
    return ret;
}

_Bool is_known_address(struct an_directory* ad, unsigned char* addr){
    int idx = sum_addr(addr);
    pthread_mutex_lock(&ad->lock);
    for(struct mac_entry* me = ad->buckets[idx]; me; me = me->next){
        if(!memcmp(me->addr, addr, 6)){
            pthread_mutex_unlock(&ad->lock);
            return 1;
        }
            /*return me->uname;*/
    }
    pthread_mutex_unlock(&ad->lock);
    return 0;
}

struct mac_entry* lookup_uname(struct an_directory* ad, unsigned char* addr){
    int idx = sum_addr(addr);
    pthread_mutex_lock(&ad->lock);
    for(struct mac_entry* me = ad->buckets[idx]; me; me = me->next){
        if(!memcmp(me->addr, addr, 6)){
            pthread_mutex_unlock(&ad->lock);
            return me;
        }
            /*return me->uname;*/
    }
    /* we store this new addr as unknown instead
     * of simply returning the string literal so that
     * we can keep track of each message in packet
     * duplicate checker even in case of reception of
     * msg packet before uname packet
     */
    /* THIS isn't entirely threadsafe
     * another thread could potentially add an entry
     * and then have it overwritten before insert_uname()
     * acquires a lock
     * TODO: insert_uname() should have an option to be run
     * with a lock already acquired
     * it can still unlock the lock, which would allow
     * keeping the line:
     *  return insert_uname(ad, addr, "unknown");
     */
    pthread_mutex_unlock(&ad->lock);
    return insert_uname(ad, addr, "unknown");
}

/* checks if nbp has been recently received. if not, adds it to buffer */
/* TODO: this is inefficient - we first check is_duplicate_packet() and then call lookup_uname() again
 * the mac_entry looked up in is_duplicate_packet() should be re-used
 */
_Bool is_duplicate_packet(struct an_directory* ad, struct new_beacon_packet* nbp){
    struct mac_entry* me = lookup_uname(ad, nbp->src_addr);
    int lock_idx = sum_addr(nbp->src_addr) % 50;

    pthread_mutex_lock(&ad->packet_storage_locks[lock_idx]);

    /*printf("checking %i stored packets for duplicates\n", me->n_packets);*/
    for(int i = 0; i < me->n_packets; ++i){
        if(!memcmp(me->nbp[i].src_addr, nbp->src_addr, sizeof(nbp->src_addr)) &&
           !memcmp(me->nbp[i].ssid, nbp->ssid, sizeof(nbp->ssid)) &&
           me->nbp[i].end_transmission == nbp->end_transmission && 
           me->nbp[i].exclude_from_builder == nbp->exclude_from_builder){
               pthread_mutex_unlock(&ad->packet_storage_locks[lock_idx]);
               return 1;
           }
    }

    if(me->pkt_idx == ad->packet_storage)
        me->pkt_idx = 0;
    memcpy(&me->nbp[me->pkt_idx], nbp, sizeof(struct new_beacon_packet));
    me->nbp[me->pkt_idx++].processed_for_msg = nbp->exclude_from_builder;

    if(me->n_packets != ad->packet_storage)++me->n_packets;

    pthread_mutex_unlock(&ad->packet_storage_locks[lock_idx]);

    return 0;
}

void p_directory(struct an_directory* ad){
    for(int i = 0; i < (int)(sizeof(ad->buckets)/sizeof(struct mac_entry*)); ++i){
        if(ad->buckets[i]){
            for(struct mac_entry* me = ad->buckets[i]; me; me = me->next){
                printf("%s@%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",  me->uname, me->addr[0], me->addr[1], me->addr[2],
                                                                         me->addr[3], me->addr[4], me->addr[5]);
            }
        }
    }
}

void add_viable_plen(struct an_directory* ad, int len, int offset){
    /*printf("%i added as viable plen with offset %i\n", len, offset);*/
    atomic_store(ad->viable_packet_len+len, offset);
}

/* returns offset of src_addr, if viable - otherwise, -1 */
int is_viable_plen(struct an_directory* ad, int len){
    int ret = atomic_load(ad->viable_packet_len+len);
    return ret;
}

#ifdef TEST
/*test this new functionality, lookup uname, then search for it - should be unknonw, then insert, then search*/
int main(){
    struct an_directory ad;
    struct new_beacon_packet* nbp_a = malloc(sizeof(struct new_beacon_packet));
    struct mac_entry* me;

    init_an_directory(&ad, 3);

    /*me = lookup_uname(&ad, (unsigned char*)"\x08\x90\x11\x00\x00\x01");*/
    printf("is duplicate: %i\n", is_duplicate_packet(&ad, nbp_a));
    *((int*)nbp_a) = 1;
    printf("is duplicate: %i\n", is_duplicate_packet(&ad, nbp_a));
    *((int*)nbp_a) = 2;
    printf("is duplicate: %i\n", is_duplicate_packet(&ad, nbp_a));
    *((int*)nbp_a) = 3;
    printf("is duplicate: %i\n", is_duplicate_packet(&ad, nbp_a));
    *((int*)nbp_a) = 4;
    printf("is duplicate: %i\n", is_duplicate_packet(&ad, nbp_a));
    *((int*)nbp_a) = 5;
    printf("is duplicate: %i\n", is_duplicate_packet(&ad, nbp_a));

    *((int*)nbp_a) = 3;
    printf("should be: %i\n", is_duplicate_packet(&ad, nbp_a));
    lookup_uname(&ad, (unsigned char*)"\x98\x90\x35\x00\x00\x01");

    /*printf("is duplicate: %i\n", is_duplicate_packet(&ad, &nbp_a));*/
    puts(lookup_uname(&ad, (unsigned char*)"\x08\x90\x11\x00\x00\x01")->uname);
    insert_uname(&ad, (unsigned char*)"\x08\x90\x11\x00\x00\x01", "asher");
    insert_uname(&ad, (unsigned char*)"\x98\x90\x35\x00\x00\x01", "eteri");
    insert_uname(&ad, (unsigned char*)"\xe6\x8d\x35\x00\x00\x01", "maxime");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x00\x01", "christopher");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "oregano");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "oregano");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "koritan");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "koan");

    puts(lookup_uname(&ad, (unsigned char*)"\x08\x90\x11\x00\x00\x01")->uname);
    puts(lookup_uname(&ad, (unsigned char*)"\x98\x90\x35\x00\x00\x01")->uname);
    puts(lookup_uname(&ad, (unsigned char*)"\xff\x90\x35\x00\x00\x01")->uname);

    p_directory(&ad);
}

#endif
