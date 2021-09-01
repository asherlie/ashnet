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

#define N_PRE_HANDLER_THREADS 10

void* repl_th(void* v_mq){
    struct mqueue* mq = v_mq;
    signed char c, buf[32] = {0};
    /* the last 4 bytes of the ssid are padded with this to allow repl-sent duplicates */
    unsigned int variety = 0;
    struct new_beacon_packet* nbp;
    _Bool new_one = 1;

    int idx = 0;
    while((c = getchar()) != -1){ 
        
        if(c != '\n')buf[idx++] = c;
        /* we send on two conditions:
         *  if idx == 32
         *  if c == '\n'
         */
        /* chopping off 5 bytes for an int and \0 because we can */
        if(idx == 27 || c == '\n'){
            nbp = malloc(sizeof(struct new_beacon_packet));
            init_new_beacon_packet(nbp);
            nbp->end_transmission = c == '\n';
            memcpy(nbp->ssid, buf, idx);

            memcpy(nbp->ssid+(32-sizeof(int)), &variety, sizeof(int));
            ++variety;

            insert_mqueue(mq, nbp, 1, 1);

            buf[idx] = 0;

            if(new_one){
                printf("%s[YOU]%s: %s", ANSI_GREEN, ANSI_RESET, ANSI_BLUE);
                new_one = 0;
            }

            printf("%s", nbp->ssid);

            if(c == '\n'){
                printf("%s\n", ANSI_RESET);
                new_one = 1;
            }

            idx = 0;
        }
    }
    #if 0
    think about message building - could just use the existing duplicate detection framework
    and not count messages as received until they get an ENDTRANSMISSION alert
    then it will attach msgs that came in by the way, each message should be sent a couple 
    times anyway this will not get in the way of msg building BECAUSE
    duplicates are always ignored

    message building will be a bit complex so it will be good to have packet handling occur 
    in a separate thread each time a packet comes in, the nbp can be added to a queue that
    processes packets one at a time 
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
    unsigned int variety = 0;

    struct new_beacon_packet nbp;
    init_new_beacon_packet(&nbp);

    /* TODO: add uname to this packet! */
    memcpy(nbp.ssid, "/UNAME", 6);
    memcpy(nbp.ssid+6, ba->uname, UNAME_LEN);
    // this is now handled by the receiving node - this space is ovewritten
    // with the second identical address field in order to confirm structure
    // of packet
    //nbp.exclude_from_builder = 1;
    /* this field is used in the pre-sending phase. this informs nbp_set_src_addr() to 
     * copy local address to BSSID field, which happens to be occupied by the boolean
     * flags as well as the extra space region of nbp
     */
    *nbp.extra_space = 1;

    while(1){
        memcpy(nbp.ssid+UNAME_LEN+6, &variety, sizeof(unsigned int));
        insert_mqueue(ba->mq, &nbp, 1, 0);
        ++variety;
        usleep(1000000);
    }
}

struct write_arg{
    struct mqueue* mq;
    struct an_directory* ad;
};

/*void prepare_write_sock(int* sock, struct sockaddr_ll* saddr){*/
/* TODO: split this into prepare_write_sock() and send_packet()
 * this will simplify the porting process
 */
void* write_th(void* v_wa){
    struct write_arg* wa = v_wa;
    struct mqueue* mq = wa->mq;
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
    ssize_t sent = 0;

    while(1){
        me = pop_mqueue_blocking(mq);
        nbp = me->packet;

        if(me->overwrite_addr){
            nbp_set_src_addr(nbp, macaddr);
        }

        /* not necessary to check return value,
         * should never be a duplicate
         * TODO: should i use a more precise approach?
         * this is possibly inefficient
         */
        (void)is_duplicate_packet(wa->ad, nbp);

        buffer = (unsigned char*)nbp;


        for(int i = 0; i < 4; ++i)
            sent += sendto(sock, buffer, sz, 0, (struct sockaddr*)&saddr, sizeof(struct sockaddr_ll));

        /* TODO: verify that sent == sizeof(struct new_beacon_packet)-4 */
        sent = 0;

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

/* this function should only be called upon receiving
 * an end transmission message. it is guaranteed to
 * return a malloc'd string
 */
/*char* build_msg(struct an_directory* ad, unsigned char* addr){*/
/* TODO: this should be done in a separate thread as to not take
 * time away from packet reception
 */
char* build_msg(struct mac_entry* me){// unsigned char* addr){
    #if 0
    there are two cases:
        1: n_packets != ad->packet_storage / n_packets != idx
        2: else

        when they are equal, things get complicated
        ignore for now
        TODO: update
    #endif
    /*struct mac_entry* me = lookup_uname(ad, addr);*/
    /* a strict upper bound for msglen is 32*n_packets */
    char* ret = calloc(1, 32*me->n_packets);

    for(int i = 0; i < me->n_packets; ++i){
        if(me->nbp[i].processed_for_msg)continue;

        me->nbp[i].processed_for_msg = 1;
        strncat(ret, (char*)me->nbp[i].ssid, 32);
        if(me->nbp[i].end_transmission)break;
    }
    return ret;
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
    struct mac_entry* me;
    char* msg;

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
            if(bp->end_transmission){
                me = lookup_uname(ad, bp->src_addr);
                msg = build_msg(me);

                printf("%s%s%s: \"%s%s%s\"\n", ANSI_RED, me->uname, ANSI_RESET, ANSI_BLUE, msg, ANSI_RESET);
                free(msg);
            }
            break;
    }

    return ret;
}

inline int min(int a, int b){
    if(a < b)return a;
    return b;
}

/* packets are viable if they fit our size constraints AND
 * they are either a /UNAME message or contain a known address
 *
 * uname messages must have the string /UNAME and have their src_addr field be
 * identical to their BSSID field
 */
/* TODO:
 * as messages come in, known offsets should be stored
 * the expensive iteration should only occur if no viable message is found
 * using existing stored buffer offsets
 *
 * TODO: this approach could lead to issues if the address of another user
 * randomly appears in a message - rare but could certainly occur
 */
_Bool is_viable_packet(struct an_directory* ad, unsigned char* buffer, struct new_beacon_packet* nbp, int len){
    /* bounds i've experimentally found */
    if(len < 92 || len > 100)return 0;

    for(int i = 0; i < len; ++i){
        memcpy(nbp->src_addr, buffer+i, min(len-i, sizeof(struct new_beacon_packet)));
        if(is_known_address(ad, nbp->src_addr))return 1;
        if(*nbp->ssid == '/' && strstr((char*)nbp->ssid+1, "UNAME") && !memcmp(nbp->src_addr, &nbp->end_transmission, 6)){
            /* since UNAME packets must now have identical BSSID and src_addr, we need to prep for handling */
            /* TODO: COULD also simply insert_uname() here to simplify */
            nbp->end_transmission = 1;
            nbp->exclude_from_builder = 1;
            return 1;
        }
    }
    return 0;
}

/* this struct is used for both pre_handler_th() and handler_th()
 *
 * in pre_handler_th(), the write_mq field is not used
 *
 * in handler_th(), the raw_mq and len fields are not used
 */
struct handler_arg{
    struct an_directory* ad;
    struct mqueue* write_mq, * raw_mq, * cooked_mq;
    int len;
};

/* > 1 of these will be running simultaneously - this code
 * checks if a packet is viable and adds it to cooked_mq
 * to be handled if it is
 */
void* pre_handler_th(void* v_ha){
    struct handler_arg* ha = v_ha;

    struct mq_entry* me;
    struct new_beacon_packet* nbp, ref_nbp;

    init_new_beacon_packet(&ref_nbp);

    while(1){
        me = pop_mqueue_blocking(ha->raw_mq);
        nbp = malloc(sizeof(struct new_beacon_packet));
        /* at this point, me->packet is just an unsigned char* cast to nbp */
        if(is_viable_packet(ha->ad, (unsigned char*)me->packet, nbp, ha->len) && 
           (!memcmp(nbp->mid_magic, ref_nbp.mid_magic, sizeof(nbp->mid_magic)))){

               insert_mqueue(ha->cooked_mq, nbp, 0, 1);
        }
    }

    return NULL;
}

/* 
 * this thread handles properly formatted packets and
 * inserts their return value to the write_mq to be sent
 */
void* handler_th(void* v_ha){
    struct handler_arg* ha = v_ha;
    /*struct mqueue* cooked_mq = v_cooked_mq;*/
    struct mq_entry* me;
    struct new_beacon_packet* hret = NULL;
    _Bool overwrite_addr, free_mem;

    while(1){
        me = pop_mqueue_blocking(ha->cooked_mq);
        if((hret = handle_packet(me->packet, ha->ad, &overwrite_addr, &free_mem))){
            insert_mqueue(ha->write_mq, hret, overwrite_addr, free_mem);
        }
    }

    return NULL;
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
    /* write_mq is used to buffer messages and
     * is popped by write_th, which then sends the
     * popped nbp
     *
     * pre_handler_mq is used to buffer raw data
     * that has been received - it checks if data
     * are viable to craft packets, if so the crafted
     *
     * packet is added to a final queue - crafted_packet_mq
     * which is popped by a handle_packet() thread
     */
    struct mqueue write_mq, pre_handler_mq, crafted_packet_mq;

    /* this can be on the stack for now */
    struct beacon_arg ba;
    struct write_arg wa;

    _Bool overwrite_addr, free_mem;

    init_an_directory(&ad, 1000);

    init_mqueue(&write_mq);
    init_mqueue(&pre_handler_mq);
    init_mqueue(&crafted_packet_mq);

    ba.mq = &write_mq;
    strncpy(ba.uname, b[1], UNAME_LEN-1);

    wa.mq = &write_mq;
    wa.ad = &ad;

    pthread_t write_pth, repl_pth, beacon_pth, pre_handler_pth[N_PRE_HANDLER_THREADS], handler_pth;

    struct handler_arg ha = {.ad = &ad, .write_mq = &write_mq, .raw_mq = &pre_handler_mq, .cooked_mq = &crafted_packet_mq};

    pthread_create(&write_pth, NULL, write_th, &wa);
    pthread_create(&repl_pth, NULL, repl_th, &write_mq);
    pthread_create(&beacon_pth, NULL, beacon_th, &ba);

    for(int i = 0; i < N_PRE_HANDLER_THREADS; ++i){
        pthread_create(pre_handler_pth+i, NULL, pre_handler_th, &ha);
    }
    pthread_create(&handler_pth, NULL, handler_th, &ha);

    init_new_beacon_packet(&ref_bp);

    while(1){
        sa_len = sizeof(struct sockaddr);
        packet_len = recvfrom(sock, buffer, buflen, 0, &s_addr, &sa_len);

        /* 4 magic bytes are sometimes magically appended to our packets :shrug:
         * make sense of this later
         */
        if(is_viable_packet(&ad, buffer, &bp, packet_len)){
        // if(packet_len == sizeof(struct new_beacon_packet) || packet_len == sizeof(struct new_beacon_packet)-4){
            // memcpy(&bp, buffer, sizeof(struct new_beacon_packet));
            /* comparing magic sections to confirm packet is from ashnet */
            resp_bp = handle_packet(&bp, &ad, &overwrite_addr, &free_mem);
            if(resp_bp)insert_mqueue(&write_mq, resp_bp, overwrite_addr, free_mem);
        }
        /*if(protocol)*/
        /*if(strstr(buffer+56, "asher"))printf("protocol: %i\n", );*/
    }

}
