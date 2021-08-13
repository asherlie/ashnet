struct mac_entry{
    char uname[32];
    struct mac_entry* next;
};

/* stores mac address, uname pairs */
struct an_directory{
    /* (0xff * 6) + 1 */
    struct mac_entry* buckets[1531];
};

void insert_uname(struct an_directory* ad, unsigned char* addr, char* uname);

void init_an_directory(struct an_directory* ad);
