#ifndef FORGE_SOCKET_H
#define FORGE_SOCKET_H
#include "forge_socket.h"


struct tcp_state *forge_socket_get_default_state();
int forge_socket_set_state(int sock, struct tcp_state *st);

#endif
