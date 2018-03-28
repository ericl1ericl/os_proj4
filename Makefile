all: threadedRE
C=/afs/nd.edu/user14/csesoft/new/bin/gcc
CFLAGS=-std=gnu99 -Wall 
LD=/afs/nd.edu/user14/csesoft/new/bin/gcc
LDFLAGS= -lpthread

threadedRE: threadedRE.o
	$(LD) threadedRE.o $(LDFLAGS) -o $@

%.o: %.c
	$(C) $(CFLAGS) -c $<

.PHONY: clean
clean: 
	rm -f threadedRE *.o 
