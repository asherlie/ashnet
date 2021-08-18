#include "ashnet_dir.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void init_an_directory(struct an_directory* ad, int storage){
    memset(ad->buckets, 0, sizeof(ad->buckets));
    ad->packet_storage = storage;
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

/* this does NOT have to be threadsafe as of now - there is only one thread
 * receiving packets
 */
struct mac_entry* insert_uname(struct an_directory* ad, unsigned char* addr, char* uname){
    struct mac_entry* last_me;
    int idx;
    if(!ad->buckets[(idx = sum_addr(addr))]){
        ad->buckets[idx] = create_mac_entry(addr, uname);
        ad->buckets[idx]->nbp = malloc(sizeof(struct new_beacon_packet)*ad->packet_storage);

        /* both == 0 until n_packets == ad->packet_storage, only then does pkt_idx loop around
         * to overwrite the oldest stored values
         */
        ad->buckets[idx]->n_packets = 0;
        ad->buckets[idx]->pkt_idx = 0;
        return ad->buckets[idx];
    }
    for(struct mac_entry* me = ad->buckets[idx]; me; me = me->next){
        /* in case of updated uname */
        if(!memcmp(me->addr, addr, 6)){
            memcpy(me->uname, uname, UNAME_LEN);
            return me;
        }
        last_me = me;
    }
    last_me->next = create_mac_entry(addr, uname);
    return last_me->next;
}

struct mac_entry* lookup_uname(struct an_directory* ad, unsigned char* addr){
    int idx = sum_addr(addr);
    for(struct mac_entry* me = ad->buckets[idx]; me; me = me->next){
        if(!memcmp(me->addr, addr, 6))
            return me;
            /*return me->uname;*/
    }
    /* we store this new addr as unknown instead
     * of simply returning the string literal so that
     * we can keep track of each message in packet
     * duplicate checker even in case of reception of
     * msg packet before uname packet
     */
    return insert_uname(ad, addr, "unknown");
}

/* checks if nbp has been recently received. if not, adds it to buffer */
/* TODO: this is inefficient - we first check is_duplicate_packet() and then call lookup_uname() again
 * the mac_entry looked up in is_duplicate_packet() should be re-used
 */
_Bool is_duplicate_packet(struct an_directory* ad, struct new_beacon_packet* nbp){
    struct mac_entry* me = lookup_uname(ad, nbp->src_addr);

    /*printf("checking %i stored packets\n", me->n_packets);*/
    for(int i = 0; i < me->n_packets; ++i){
        if(!memcmp(me->nbp+i, nbp, sizeof(struct new_beacon_packet)))return 1;
    }

    if(me->pkt_idx == ad->packet_storage)
        me->pkt_idx = 0;
    memcpy(&me->nbp[me->pkt_idx++], nbp, sizeof(struct new_beacon_packet));

    if(me->n_packets != ad->packet_storage)++me->n_packets;

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
