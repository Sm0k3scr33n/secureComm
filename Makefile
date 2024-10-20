CC = gcc
CFLAGS = -Wall -O2 -I/usr/local/include -I/usr/include/json-c
LDFLAGS = -L/usr/local/lib -l:bcrypt.a -ljson-c -lssl -lcrypto -lXm -lXt -lX11

all: server client generate_config

server: server.o
	$(CC) -o server server.o $(CFLAGS) $(LDFLAGS)

client: client.o
	$(CC) -o client client.o $(CFLAGS) $(LDFLAGS)

generate_config: generate_config.o
	$(CC) -o generate_config generate_config.o $(CFLAGS) $(LDFLAGS)

server.o: server.c
	$(CC) -c server.c $(CFLAGS)

client.o: client.c
	$(CC) -c client.c $(CFLAGS)
	
generate_config.o: generate_config.c
	$(CC) -c generate_config.c $(CFLAGS)

clean:
	rm -f *.o server client generate_config

