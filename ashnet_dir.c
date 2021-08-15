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

char* lookup_uname(struct an_directory* ad, unsigned char* addr){
    int idx = sum_addr(addr);
    for(struct mac_entry* me = ad->buckets[idx]; me; me = me->next){
        if(!memcmp(me->addr, addr, 6))
            return me->uname;
    }
    /* TODO: should we just return NULL in this case?
     * we could just print the MAC instead of a string
     */
    return "unknown";
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

int main(){
    struct an_directory ad;
    init_an_directory(&ad);

    insert_uname(&ad, (unsigned char*)"\x08\x90\x11\x00\x00\x01", "asher");
    insert_uname(&ad, (unsigned char*)"\x98\x90\x35\x00\x00\x01", "eteri");
    insert_uname(&ad, (unsigned char*)"\xe6\x8d\x35\x00\x00\x01", "maxime");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x00\x01", "christopher");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "oregano");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "oregano");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "koritan");
    insert_uname(&ad, (unsigned char*)"\x00\x00\x00\x00\x01\x00", "koan");

    puts(lookup_uname(&ad, (unsigned char*)"\x08\x90\x11\x00\x00\x01"));
    puts(lookup_uname(&ad, (unsigned char*)"\x98\x90\x35\x00\x00\x01"));
    puts(lookup_uname(&ad, (unsigned char*)"\xff\x90\x35\x00\x00\x01"));

    p_directory(&ad);
}
#endif
