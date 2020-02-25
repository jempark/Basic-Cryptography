CC=gcc
OPENSSL=/home/jay/Desktop/HSecurity/Lab01/openssl
INCLUDE=$(OPENSSL)/include/
CFLAGS=-c -I$(INCLUDE) 

all: measureRSA measureAES client

measureRSA: measureRSA.c
	$(CC) measureRSA.c -I$(INCLUDE) -L$(OPENSSL) -o measureRSA $(OPENSSL)/libcrypto.a -ldl -lpthread

measureAES: measureAES.c
	$(CC) measureAES.c -I$(INCLUDE) -L$(OPENSSL) -o measureAES $(OPENSSL)/libcrypto.a -ldl -lpthread

client: client.c
	$(CC) client.c -I$(INCLUDE) -L$(OPENSSL) -o client $(OPENSSL)/libcrypto.a -ldl -lpthread

clean:
	rm -rf measureRSA measureAES client
