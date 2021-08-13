CC=gcc
CFLAGS= -Wall -Wextra -Wpedantic -Werror -O3 -lpthread

all: sr

packet.o: packet.c packet.h

sr: sr.c packet.o

.PHONY:
clean:
	rm -f sr *.o
