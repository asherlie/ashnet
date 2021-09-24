#include "packet.h"
#include <string.h>

void init_beacon_packet(struct beacon_packet* bp){
    unsigned char rth[56] = 
    /*'\x00', '\x00', '\x38', '\x00', '\x6f', '\x08', '\x00', '\xc0'*/


                                                /* 08:11:96:99 is part of IP addr, is this dynamically set? */
"\x00\x00\x38\x00\x6f\x08\x00\xc0\x01\x00\x00\x40\x08\x11\x96\x99" \
"\x7b\xb1\x61\x0c\x00\x00\x00\x00\x10\x02\x6c\x09\x80\x04\xe8\xa6" \
"\x00\x0b\x00\x10\x18\x00\x03\x00\x02\x00\x00\x4c\x00\x10\x18\x03" \
"\x06\x00\xaa\xd7\xc8\x01\xf2\x56";

    unsigned char mstr[4] = "\x80\x00\x00\x00";
    unsigned char daddr[6] = "\xff\xff\xff\xff\xff\xff";
    unsigned char mgck2[5] = "\x64\x00\x00\x00\x00";
    unsigned char tag[4] = "\x00\x9f\xe0\x02";

/*
"\x08\x11\x96\x99\x37\x90\x08\x11\x96\x99\x37\x90\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00

\x0b\x4a\x4b" \
"\x4e\x45\x54\x3a\x4d\x45\x4c\x4c\x6f\xc1\xaa\xd7\xc7"
*/



    memcpy(bp->radiotap_hdr, rth, 56);
    memcpy(bp->magic, mstr, 4);
    memcpy(bp->dest_addr, daddr, 6);
    memset(bp->zeroes, 0, 10);
    memcpy(bp->more_magic, mgck2, 5);
    /* maxlen for ssid == 32b */
    bp->ssid_len = '\x20';
    bp->ssid_len = '\x0b';
    memcpy(bp->tag, tag, 4);
}

void init_new_beacon_packet(struct new_beacon_packet* bp){
/*magic until 08,11*/ // (28 bytes of magic, src starts at 29)-1
    unsigned char packet[] = 
     {
    '\x00', '\x00', '\x12', '\x00', '\x2e', '\x48', '\x00', '\x00', '\x2e', '\x02', '\x6c', '\x09', '\xa0', '\x00', '\xe5', '\x03',
    '\x00', '\x00', '\x80', '\x00', '\x00', '\x00', '\xff', '\xff', '\xff', '\xff', '\xff', '\xff', '\x08', '\x11', '\x96', '\x99',
    '\x37', '\x90', '\x08', '\x11', '\x96', '\x99', '\x37', '\x90', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
    '\x00', '\x00', '\x64', '\x00', '\x00', '\x00', '\x00', '\x20', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', 
    '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x6a', '\x00', '\x85', '\xc3'
     };

     memcpy(bp, packet, sizeof(struct new_beacon_packet));
     bp->uname_beacon = 0;
     /* defaulting to end_transmission, can be set otherwise in repl() if necessary */
     bp->end_transmission = 1;
     bp->exclude_from_builder = 0;
}

void nbp_set_src_addr(struct new_beacon_packet* bp, unsigned char* src_addr){
    memcpy(bp->src_addr, src_addr, 6);
    /* this is used for uname packets */
    if(bp->uname_beacon){
        memcpy(&bp->end_transmission, src_addr, 6);
    }
}

void set_src(struct beacon_packet* bp, unsigned char* src_addr){

    memcpy(bp->src_addr, src_addr, 6);
    memcpy(bp->src_bssid, src_addr, 6);
}
