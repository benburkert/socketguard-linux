#include <net/sock.h>

#ifndef _SG_RECV_H
#define _SG_RECV_H

int sg_recv_handshake_initiation(struct sock *sk);
int sg_recv_handshake_response(struct sock *sk);

#endif /* _SG_RECV_H */
