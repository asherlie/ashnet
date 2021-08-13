#include "ashnet_dir.h"
#include <string.h>
#include <stdio.h>

void init_an_directory(struct an_directory* ad){
    memset(ad->buckets, 0, sizeof(ad->buckets));
}

void insert_uname(struct an_directory* ad, unsigned char* addr, char* uname){
}

int main(){
    struct an_directory ad;
    init_an_directory(&ad);
}
