CFLAGS=-I../

targets=test bind-test nc

all: $(targets)

nc: nc.c libforge_socket.o
	$(CC) $(CFLAGS) -o $@ $^
