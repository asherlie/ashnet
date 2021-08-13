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

#include "packet.h"

/*void prepare_write_sock(int* sock, struct sockaddr_ll* saddr){*/
void* write_th(void* arg){
    (void)arg;
    int sock = socket(AF_PACKET, SOCK_RAW, 0);
    struct ifreq ifr = {0};
    struct ifreq if_mac = {0};
    struct new_beacon_packet nbp;
    int sz = sizeof(struct new_beacon_packet)-4;
    unsigned char* buffer;

    strncpy(ifr.ifr_name, "wlp3s0", IFNAMSIZ-1);
    strncpy(if_mac.ifr_name, "wlp3s0", IFNAMSIZ-1);

    printf("IOCTL: %i\n", ioctl(sock, SIOCGIFINDEX, &ifr));
    if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1)perror("IOCTL");
    if(ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0)perror("HWADDR");

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
    init_new_beacon_packet(&nbp);
    nbp_set_bssid(&nbp, (unsigned char*)"\x08\x11\x96\x99\x37\x90");
    nbp_set_src_addr(&nbp, (unsigned char*)"\x08\x11\x96\x99\x37\x90");
    buffer = (unsigned char*)&nbp;

    /*saddr.*/
    /*while(getchar() != 'q'){*/
    char* ln = NULL;
    size_t lsz;
    int llen;
    while((llen = getline(&ln, &lsz, stdin)) != EOF){
        if(llen > 32){
            ln[32] = 0;
            llen = 32;
        }
        memcpy(nbp.ssid, (unsigned char*)ln, llen);
        /*printf("send: %li\n", sendto(sock, buffer, sz, 0, (struct sockaddr*)&saddr, sizeof(struct sockaddr_ll)));*/
        printf("sent %li bytes into the void: \"%s\"\n",
            sendto(sock, buffer, sz, 0, (struct sockaddr*)&saddr, sizeof(struct sockaddr_ll)), ln);
    }
    close(sock);

    return NULL;
}

int main(){
    /* TODO: ETH_P_ALL shouldn't be used, we should filter out the noise */
	struct sockaddr s_addr;
    socklen_t sa_len;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), packet_len;
    /* if we're filtering properly, we can keep this buffer small */
    unsigned char* buffer = malloc(100000);
    struct new_beacon_packet bp, ref_bp;

    init_new_beacon_packet(&ref_bp);

    while(1){
        packet_len = recvfrom(sock, buffer, 100000, 0, &s_addr, &sa_len);

        if(packet_len == sizeof(struct new_beacon_packet)){
            memcpy(&bp, buffer, sizeof(struct new_beacon_packet));
            if(memcmp(bp.magic_hdr, ref_bp.magic_hdr, sizeof(bp.magic_hdr)))break;
            printf("\"%s\"\n", bp.ssid);
        }
        /*if(protocol)*/
        /*if(strstr(buffer+56, "asher"))printf("protocol: %i\n", );*/
    }

}
