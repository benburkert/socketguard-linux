#ifndef _SG_PROTO_H
#define _SG_PROTO_H

#include <net/sock.h>

void init_protos(struct sock *sk);
struct proto *get_tcp_proto(struct sock *sk);
struct proto *get_sg_proto(struct sock *sk);

int sg_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		  unsigned int optlen);

#endif /* _SG_PROTO_H */
