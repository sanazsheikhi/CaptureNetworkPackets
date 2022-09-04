#Make file for mydump
CC=gcc
CFLAGS= -g
LIBS= -lpcap

mydump:    
	$(CC) mydump.c $(CFLAGS) $(LIBS) -o mydump
clean:
	rm -f mydump
