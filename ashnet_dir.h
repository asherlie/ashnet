#define UNAME_LEN 20

/* each entry also stores n most recent packets sent by addr */
struct mac_entry{
    unsigned char addr[6];
    char uname[UNAME_LEN];
    struct new_beacon_packet* nbp;
    int n_packets;
    struct mac_entry* next;
};

/* stores mac address, uname pairs */
struct an_directory{
    int packet_storage;
    /* (0xff * 6) + 1 */
    struct mac_entry* buckets[1531];
};

void init_an_directory(struct an_directory* ad, int storage);
void insert_uname(struct an_directory* ad, unsigned char* addr, char* uname);
char* lookup_uname(struct an_directory* ad, unsigned char* addr);
void p_directory(struct an_directory* ad);
