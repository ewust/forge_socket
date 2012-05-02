
obj-m += forge_socket.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install: forge_socket.ko
	rmmod forge_socket
	insmod forge_socket.ko

test: bind-test.c test.c
	gcc test.c -o test
	gcc bind-test.c -o bind-test
	./test
