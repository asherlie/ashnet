#ifndef _PACKET_H
#define _PACKET_H
//#include 
struct beacon_packet{
    unsigned char radiotap_hdr[56];
    unsigned char magic[4];
    unsigned char dest_addr[6];
    unsigned char src_addr[6];
    unsigned char src_bssid[6];
    /* sequence number, timestamp - 0s seem to work */
    unsigned char zeroes[10];
    /* interval, imm block ack, tag_no */
    unsigned char more_magic[5];
    unsigned char ssid_len;
    //unsigned char ssid[32];
    /* trying with 11 for now to test JKNET:MELLo */
    unsigned char ssid[11];
    /* this might differ based on length, not sure */
    unsigned char tag[4];
};

/* sizeof(struct new_beacon_packet)-4 should be sent */
/* packing is almost certainly unnecessary bc all fields are unsigned
 * chars, but couldn't hurt
 */
struct __attribute__((__packed__)) new_beacon_packet{
    unsigned char magic_hdr[28];
    unsigned char src_addr[6];
    _Bool end_transmission;
    _Bool exclude_from_builder;
    _Bool processed_for_msg;
    /*
     * this flag is used both in senders, and receivers
     * in senders it's used to mark a packet as needing a duplicate src addr field to
     * nbp_set_src_addr()
     *
     * in receivers,
     * this flag will be set if pre-handler/is_viable() notices a /uname
     * it's good to have this here in order to not search for /uname twice
     * it's also helpful to have this because it enables us to not check for /uname
     * in packets of predictable sizes until packet handling
     * but still lets us check for /uname in pre-handling with novel packet sizes
    */
    _Bool uname_beacon;
    unsigned char extra_space[2];
    /* last byte of this is length of ssid, which is always 32b */
    unsigned char mid_magic[16];
    unsigned char ssid[32];
    /* this should not be included when sending, it's recalculated implicitly */
    unsigned char end_magic[4];
};

/* sets all fields but nvm(ssid_len), ssid, src addrs*/
void init_beacon_packet(struct beacon_packet* bp);
void init_new_beacon_packet(struct new_beacon_packet* bp);
void set_src(struct beacon_packet* bp, unsigned char* src_addr);

void nbp_set_bssid(struct new_beacon_packet* bp, unsigned char* bssid);
void nbp_set_src_addr(struct new_beacon_packet* bp, unsigned char* src_addr);
#endif
