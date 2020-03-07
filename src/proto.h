#ifndef _SG_PROTO_H
#define _SG_PROTO_H

#include <net/sock.h>

void init_protos(struct sock *sk);
struct proto *get_tcp_proto(struct sock *sk);
struct proto *get_sg_proto(struct sock *sk);

#endif /* _SG_PROTO_H */
