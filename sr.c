#include <sys/socket.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "packet.h"

int main(){
    /* TODO: ETH_P_ALL shouldn't be used, we should filter out the noise */
	struct sockaddr s_addr;
    socklen_t sa_len;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)), packet_len;
    /* if we're filtering properly, we can keep this buffer small */
    unsigned char* buffer = malloc(100000);
    struct new_beacon_packet bp;

    while(1){
        packet_len = recvfrom(sock, buffer, 100000, 0, &s_addr, &sa_len);

        if(packet_len == sizeof(struct new_beacon_packet)){
            puts("GOT IT :)");
        }
        /*if(protocol)*/
        /*if(strstr(buffer+56, "asher"))printf("protocol: %i\n", );*/
    }

}
