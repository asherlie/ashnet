#include <pthread.h>

#include "packet.h"

#define UNAME_LEN 20

/* each entry also stores n most recent packets sent by addr */
struct mac_entry{
    unsigned char addr[6];
    char uname[UNAME_LEN];
    struct new_beacon_packet* nbp;
    int n_packets, pkt_idx;
    struct mac_entry* next;
};

/* stores mac address, uname pairs */
/* as of now, an_directory also stores
 * the number of the number of ignored
 * packets of unknown size that have been
 * received in order to know when to accept
 * one
 */
struct an_directory{
    pthread_mutex_t lock;

    /* instead of having one for each MAC, 
     * we use 50 and just do some modulus
     * on sum_addr() to select which lock to use
     */
    pthread_mutex_t packet_storage_locks[50];
    int packet_storage;
    /* (0xff * 6) + 1 */
    struct mac_entry* buckets[1531];

    /* TODO: this should be dynamically resized */
    /* this is atomic to ensure that if we're checking for valid length
     * there's no chance of a false positive due to being midway through
     * an insertion
     * all indices will be initialized to -1, an impossible value
     */
    _Atomic int viable_packet_len[1000];

    _Atomic int ignored_packets;
};

void init_an_directory(struct an_directory* ad, int storage);
struct mac_entry* insert_uname(struct an_directory* ad, unsigned char* addr, char* uname);
_Bool is_known_address(struct an_directory* ad, unsigned char* addr);
struct mac_entry* lookup_uname(struct an_directory* ad, unsigned char* addr);
_Bool is_duplicate_packet(struct an_directory* ad, struct new_beacon_packet* nbp);
void p_directory(struct an_directory* ad);

void add_viable_plen(struct an_directory* ad, int len, int offset);
int is_viable_plen(struct an_directory* ad, int len);
