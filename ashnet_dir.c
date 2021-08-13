#include "ashnet_dir.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void init_an_directory(struct an_directory* ad){
    memset(ad->buckets, 0, sizeof(ad->buckets));
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
void insert_uname(struct an_directory* ad, unsigned char* addr, char* uname){
    struct mac_entry* last_me;
    int idx;
    if(!ad->buckets[(idx = sum_addr(addr))]){
        ad->buckets[idx] = create_mac_entry(addr, uname);
        return;
    }
    for(struct mac_entry* me = ad->buckets[idx]; me; me = me->next){
        /* in case of updated uname */
        if(!memcmp(me->addr, addr, 6)){
            memcpy(me->uname, uname, UNAME_LEN);
            return;
        }
        last_me = me;
    }
    last_me->next = create_mac_entry(addr, uname);
}

int main(){
    struct an_directory ad;
    init_an_directory(&ad);

    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x00\x01", "christopher");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "oregano");
}
