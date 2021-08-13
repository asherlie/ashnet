CC=gcc
CFLAGS= -Wall -Wextra -Wpedantic -Werror -O3 -lpthread

all: sr

packet.o: packet.c packet.h
ashnet_dir.o: ashnet_dir.c ashnet_dir.h
mq.o: mq.c mq.h

sr: sr.c packet.o ashnet_dir.o mq.o

.PHONY:
clean:
	rm -f sr *.o
