#include "libforge_socket.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main()
{
    struct tcp_state *st;

    st = forge_socket_get_default_state();
    int sock = socket(AF_INET, SOCK_FORGE, 0);


    st->src_ip = inet_addr("141.212.111.35");
    st->dst_ip = inet_addr("141.212.108.239");
    st->sport = htons(12345);
    st->dport = htons(54321);
    st->seq = 0x01020304;
    st->ack = 0x05060708;

    st->snd_una = st->seq;

    if (forge_socket_set_state(sock, st) != 0) {
        printf("fail\n");
        return 1;
    }

    sleep(5);
    printf("sending/receiving...\n");

    char *msg = "hello";
    int r = send(sock, msg, strlen(msg), 0);
    printf("send %d bytes\n", r);

    sleep(10);

    return 0;

}
