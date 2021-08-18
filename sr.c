#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <linux/if_packet.h>

#include <pthread.h>

/*#include "packet.h"*/
#include "ashnet_dir.h"
#include "mq.h"

#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_RESET   "\x1b[0m"

void* repl_th(void* v_mq){
    struct mqueue* mq = v_mq;
    char* ln = NULL;
    size_t lsz;
    int llen;

    /* the last 4 bytes of the ssid are padded with this to allow repl-sent duplicates */
    unsigned int variety = 0;
    int padlen;
    struct new_beacon_packet* nbp;

    while((llen = getline(&ln, &lsz, stdin)) != EOF){
        ln[llen-1] = 0;
        if(llen > 32){
            ln[31] = 0;
            llen = 32;
        }

        nbp = malloc(sizeof(struct new_beacon_packet));
        init_new_beacon_packet(nbp);
        memcpy(nbp->ssid, (unsigned char*)ln, llen);
        /* calculating number of variety bytes we can add to the end of ssid field */
        padlen = sizeof(int);
        if(llen+sizeof(int) >= 32)padlen -= (32-llen);
        memcpy(nbp->ssid+(32-sizeof(int)), &variety, padlen);
        ++variety;

        insert_mqueue(mq, nbp, 1, 1);
        printf("%s[YOU]%s: %s%s%s\n", ANSI_GREEN, ANSI_RESET, ANSI_BLUE, nbp->ssid, ANSI_RESET);
    }
    #if 0
    think about message building - could just use the existing duplicate detection framework
    and not count messages as received until they get an ENDTRANSMISSION alert
    then it will attach msgs that came in

    by the way, each message should be sent a couple times anyway
    this will not get in the way of msg building BECAUSE
    duplicates are always ignored

    message building will be a bit complex so it will be good to have packet handling occur in a separate thread
    each time a packet comes in, the nbp can be added to a queue that processes packets one at a time
    #endif

    return NULL;
}

/* contaings pointer to mq, uname */
struct beacon_arg{
    char uname[UNAME_LEN];
    struct mqueue* mq;
};

/* uname alerts should also be spread across the network */
void* beacon_th(void* v_ba){
    struct beacon_arg* ba = v_ba;

    struct new_beacon_packet nbp;
    init_new_beacon_packet(&nbp);

    /* TODO: add uname to this packet! */
    memcpy(nbp.ssid, "/UNAME", 6);
    memcpy(nbp.ssid+6, ba->uname, UNAME_LEN);

    while(1){
        insert_mqueue(ba->mq, &nbp, 1, 0);
        usleep(1000000);
    }
}

/*void prepare_write_sock(int* sock, struct sockaddr_ll* saddr){*/
/* TODO: split this into prepare_write_sock() and send_packet()
 * this will simplify the porting process
 */
void* write_th(void* v_mq){
    struct mqueue* mq = v_mq;
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    struct ifreq ifr = {0};
    struct ifreq if_mac = {0};
    struct new_beacon_packet* nbp;
    int sz = sizeof(struct new_beacon_packet)-4;
    unsigned char macaddr[6];
    unsigned char* buffer;

    strncpy(ifr.ifr_name, "wlp3s0", IFNAMSIZ-1);
    strncpy(if_mac.ifr_name, "wlp3s0", IFNAMSIZ-1);

    if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1)perror("IOCTL");
    if(ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0)perror("HWADDR");
    memcpy(macaddr, if_mac.ifr_addr.sa_data, 6);

    if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void*)&ifr, sizeof(ifr)) < 0)perror("setsockopt");

    /*printf("sock: %i\n", sock);*/
    /*printf("send: %li\n", send(sock, buffer, sz, 0));*/
    struct sockaddr_ll saddr;
    saddr.sll_ifindex = ifr.ifr_ifindex;
    /*printf("somehow: %i\n", saddr.sll_ifindex);*/
    saddr.sll_halen = ETH_ALEN;
    
    /*
     * struct beacon_packet pkt;
     * init_beacon_packet(&pkt);
     * set_src(&pkt, (unsigned char*)"\x08\x11\x96\x99\x37\x90");
     * int sz = sizeof(struct beacon_packet);
    */

    /* setup is now done */

    struct mq_entry* me;
    ssize_t sent;

    while(1){
        me = pop_mqueue_blocking(mq);
        nbp = me->packet;
        if(me->overwrite_addr){
            nbp_set_bssid(nbp, macaddr);
            nbp_set_src_addr(nbp, macaddr);
        }
        buffer = (unsigned char*)nbp;
        sent = sendto(sock, buffer, sz, 0, (struct sockaddr*)&saddr, sizeof(struct sockaddr_ll));//, nbp->ssid);
        /* TODO: verify that sent == sizeof(struct new_beacon_packet)-4 */
        (void)sent;

        /* bad solution, should probably add another option for mq_entries
         * that enables system messages to be hidden from the user
         * instead of just not printing all messages that begin with /
         */
        if(me->free_mem)free(nbp); 
    }

    return NULL;

#if 0
    init_new_beacon_packet(&nbp);

    nbp_set_bssid(&nbp, macaddr);
    nbp_set_src_addr(&nbp, macaddr);

    buffer = (unsigned char*)&nbp;

    /*saddr.*/
    /*while(getchar() != 'q'){*/
    char* ln = NULL;
    size_t lsz;
    int llen;
    while((llen = getline(&ln, &lsz, stdin)) != EOF){
        ln[llen-1] = 0;
        if(llen > 32){
            ln[31] = 0;
            llen = 32;
        }
        memcpy(nbp.ssid, (unsigned char*)ln, llen);
        /*printf("send: %li\n", sendto(sock, buffer, sz, 0, (struct sockaddr*)&saddr, sizeof(struct sockaddr_ll)));*/
        printf("sent %li bytes into the void: \"%s\"\n",
            sendto(sock, buffer, sz, 0, (struct sockaddr*)&saddr, sizeof(struct sockaddr_ll)), ln);
    }
    close(sock);

    return NULL;
#endif
}

void p_usage(){
    puts("usage:");
}

/* TODO: there should be a separate packet handler thread
 * as of now, main() calls handle_packet() each time a new
 * packet is read. this will be a bottleneck when many msgs
 * come in rapidly
 * messages should be added to a queue and handled by a separate
 * thread
 * in order to keep packet reading as fast as possible
 */
#if 0
i will disable spamming, the spam detection will double as a way to check
if we have already received a packet
this might occur if nearby users are `spreading` a packet
could also RANDOMIZE some field of the packet, possibly timestamp, idk
play around with what enables the packet to still be sent
if a packet received is IDENTICAL to any of the last `n` packets
received by a given MAC, then do nt print it or spread it

does not even have to be exact, we can increase `n` and keep track of broader
buckets, looking for identical packets
can just check all packets with the same sum_addr()

ooh and if we are checking for duplicates, then we can just send 2 or 4
identical packets at a time
if its received more than once, it will just get filtered out
increases odds of good transmission, esp. towards upper bounds of range

ALSO
i should add a preprocessor mode that echoes messages and confirms they were received
useful for testing range, for example

ALSO
think about how to implement message builder, could set two bytes x/y - this 
is message x of a total y

it is perhaps simpler to just have m(x of y), but could instead have a recv and request system
where any node that is already received can fulfill the request
they request until the message is complete
#endif

/* handle_packet() returns a packet to send in response
 * this makes the assumption that there's strictly one
 * packet to send in response to any given received packet
 *
 * overwrite_addr and free_mem are set if ret != NULL
 */
struct new_beacon_packet* handle_packet(struct new_beacon_packet* bp, struct an_directory* ad,
                                        _Bool* overwrite_addr, _Bool* free_mem){
    struct new_beacon_packet* ret = NULL;

    if(is_duplicate_packet(ad, bp))return NULL;

    /* set up return value of identical packet */
    /* TODO: will final 4 bytes of padding cause problems? 
     * could ignore these in duplicate detection
     * these, as well as some other bytes, may be re-computed
     */
    ret = malloc(sizeof(struct new_beacon_packet));
    memcpy(ret, bp, sizeof(struct new_beacon_packet));
    *overwrite_addr = 0;
    *free_mem = 1;

    switch(*bp->ssid){
        case '/':
            if(strstr((char*)bp->ssid+1, "UNAME")){
                insert_uname(ad, bp->src_addr, (char*)bp->ssid+6);
            }
            break;
        /* [E]cho - useful for testing range */
        case 'E':
            /* as of now, insert_mqueue() handles the setting of send fields
             * this will cause problems when we need to spread messages
             * as well as echo,
             * these fields will need to be moved to the packet itself
             * see note in mq.c
             */
            init_new_beacon_packet(ret);
            *overwrite_addr = 0;
            *free_mem = 1;
            memcpy(ret->ssid, "echo", 4);
            memcpy(ret->ssid+4, bp->ssid, 32-4);
            break;
        default:
            printf("%s%s%s: \"%s%s%s\"\n", ANSI_RED, lookup_uname(ad, bp->src_addr)->uname, ANSI_RESET, ANSI_BLUE, bp->ssid, ANSI_RESET);
            /* TODO: should we print MAC in case of "unknown" */
            /*printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:\"%s\"\n", bp.src_addr[0], bp.src_addr[1], bp.src_addr[2], */
                                                 /*bp.src_addr[3], bp.src_addr[4], bp.src_addr[5], bp.ssid);*/
            break;
    }

    return ret;
}

int main(int a, char** b){
    if(a < 2){
        p_usage();
        return EXIT_FAILURE;
    }
    /* TODO: ETH_P_ALL shouldn't be used, we should filter out the noise */
	struct sockaddr s_addr;
    socklen_t sa_len;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), packet_len;
    /* if we're filtering properly, we can keep this buffer small */
    int buflen = sizeof(struct new_beacon_packet)*2;
    unsigned char* buffer = malloc(buflen);
    struct new_beacon_packet bp, ref_bp, * resp_bp;

    struct an_directory ad;
    struct mqueue mq;

    /* this can be on the stack for now */
    struct beacon_arg ba;

    _Bool overwrite_addr, free_mem;

    init_an_directory(&ad, 100);
    init_mqueue(&mq);

    ba.mq = &mq;
    strncpy(ba.uname, b[1], UNAME_LEN-1);

    pthread_t write_pth, repl_pth, beacon_pth;

    pthread_create(&write_pth, NULL, write_th, &mq);
    pthread_create(&repl_pth, NULL, repl_th, &mq);
    pthread_create(&beacon_pth, NULL, beacon_th, &ba);

    init_new_beacon_packet(&ref_bp);

    while(1){
        packet_len = recvfrom(sock, buffer, buflen, 0, &s_addr, &sa_len);

        if(packet_len == sizeof(struct new_beacon_packet)){
            memcpy(&bp, buffer, sizeof(struct new_beacon_packet));
            /* comparing magic sections to confirm packet is from ashnet */
            if(memcmp(bp.mid_magic, ref_bp.mid_magic, sizeof(bp.mid_magic)))continue;
            resp_bp = handle_packet(&bp, &ad, &overwrite_addr, &free_mem);
            if(resp_bp)insert_mqueue(&mq, resp_bp, overwrite_addr, free_mem);
        }
        /*if(protocol)*/
        /*if(strstr(buffer+56, "asher"))printf("protocol: %i\n", );*/
    }

}
