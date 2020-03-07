#ifndef _SG_PROTO_H
#define _SG_PROTO_H

#include <net/sock.h>

int ulp_init(struct sock *sk);
void ulp_clone(const struct request_sock *req, struct sock *newsk,
	      const gfp_t priority);
void ulp_release(struct sock *sk);

void init_protos(struct sock *sk);
struct proto *get_tcp_proto(struct sock *sk);
struct proto *get_sg_proto(struct sock *sk);

struct sock *sg_accept(struct sock *sk, int flags, int *err, bool kern);
int sg_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		  int __user *optlen);
int sg_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		  unsigned int optlen);

#endif /* _SG_PROTO_H */
