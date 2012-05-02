#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "forge_socket.h"
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void print_state(struct tcp_state *st)
{
    printf("\tsrcip: %x:%d\n\tdstip:%x:%d\n", \
           ntohl(st->src_ip), ntohs(st->sport), \
           ntohl(st->dst_ip), ntohs(st->dport));
    printf("\tseq: %x\n\tack:%x\n", st->seq, st->ack);
    printf("\tsnd_una: %x\n", st->snd_una);
    printf("\ttstamp_ok: %d\n", st->tstamp_ok);
    printf("\tsack_ok: %d\n", st->sack_ok);
    printf("\twscale_ok: %d\n", st->wscale_ok);
    printf("\tecn_ok: %d\n", st->ecn_ok);
    printf("\tsnd_wscale: %d\n", st->snd_wscale);
    printf("\trcv_wscale: %d\n", st->rcv_wscale);
}



int main()
{
    int sock;
    struct sockaddr_in sin;
    sock = socket(AF_INET, SOCK_FORGE, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = inet_addr("0.0.0.0");
    sin.sin_port        = htons(1234);

    int val = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return -1;
    }

    if (listen(sock, 5) < 0) {
        perror("listen");
        return -1;
    }
    printf("listening...\n");

    int len = sizeof(sin);
    int sock_recv = accept(sock, (struct sockaddr *)&sin, &len);
    if (sock_recv < 0) {
        perror("accept");
        return 1;
    }
    printf("got connection from %s\n", inet_ntoa(sin.sin_addr));
    
    struct tcp_state state;
    int r;
    if (send(sock_recv, "hello", 5, 0) < 0) {
        perror("send");
        return -1;
    }

    r = getsockopt(sock_recv, IPPROTO_TCP, TCP_STATE, &state, &len);
    if (r != 0) {
        perror("getsockopt");
        return -1;
    }
    print_state(&state);
    

    return 0;
}
