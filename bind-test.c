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
    printf("\tfamily: %x\n\tstate: %x\n\trefcnt: %x\n\tbound_dev_if: %d\n", \
           st->skc_family, st->skc_state, st->skc_refcnt, st->skc_bound_dev_if);
    printf("\tsnd_una: %x\n", st->snd_una);
    printf("\ttstamp_ok: %d\n", st->tstamp_ok);
    printf("\tsack_ok: %d\n", st->sack_ok);
    printf("\twscale_ok: %d\n", st->wscale_ok);
    printf("\tecn_ok: %d\n", st->ecn_ok);
    printf("\tsnd_wscale: %d\n", st->snd_wscale);
    printf("\trcv_wscale: %d\n", st->rcv_wscale);
    //Debug:
    printf("\tsnd_wnd: %x\n", st->snd_wnd);
    printf("\trcv_wnd: %x\n", st->rcv_wnd);
    printf("\tdefault_ca_ops: %d\n", st->icsk_ca_ops_default);
    printf("\ttcp_header_len: %d\n", st->tp_header_len);
    printf("\tcopied_seq: %x\n", st->tp_copied_seq);
    printf("\trcv_wup: %x\n", st->tp_rcv_wup);
    printf("\tsnd_sml: %x\n", st->tp_snd_sml);
    printf("\tca_name: %s\n", st->icsk_ca_name);
    printf("\tinet_num: %d\n", st->inet_num);
    printf("\thas_icsk_bind_hash: %d\n", st->has_icsk_bind_hash);
    
    
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
    if (send(sock_recv, "hello\n", 6, 0) < 0) {
        perror("send");
        return -1;
    }

    len = sizeof(state);
    r = getsockopt(sock, IPPROTO_TCP, TCP_STATE, &state, &len);
    if (r != 0) {
        perror("getsockopt");
        return -1;
    }
    print_state(&state);

    sleep(5);
    

    return 0;
}
