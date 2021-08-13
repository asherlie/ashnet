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

void* repl_th(void* v_mq){
    struct mqueue* mq = v_mq;
    char* ln = NULL;
    size_t lsz;
    int llen;
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
        insert_mqueue(mq, nbp, 1, 1);
    }

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
    memcpy(nbp.ssid, "UNAME:", 6);
    memcpy(nbp.ssid+6, ba->uname, UNAME_LEN);

    while(1){
        insert_mqueue(ba->mq, &nbp, 1, 0);
        usleep(1000000);
    }
}

/*void prepare_write_sock(int* sock, struct sockaddr_ll* saddr){*/
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

    while(1){
        me = pop_mqueue_blocking(mq);
        nbp = me->packet;
        if(me->overwrite_addr){
            nbp_set_bssid(nbp, macaddr);
            nbp_set_src_addr(nbp, macaddr);
        }
        buffer = (unsigned char*)nbp;
        printf("sent %li bytes into the void: \"%s\"\n",
            sendto(sock, buffer, sz, 0, (struct sockaddr*)&saddr, sizeof(struct sockaddr_ll)), nbp->ssid);
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
    struct new_beacon_packet bp, ref_bp;

    struct mqueue mq;

    /* this can be on the stack for now */
    struct beacon_arg ba;

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
            printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x:\"%s\"\n", bp.src_addr[0], bp.src_addr[1], bp.src_addr[2], 
                                                 bp.src_addr[3], bp.src_addr[4], bp.src_addr[5], bp.ssid);
        }
        /*if(protocol)*/
        /*if(strstr(buffer+56, "asher"))printf("protocol: %i\n", );*/
    }

}
