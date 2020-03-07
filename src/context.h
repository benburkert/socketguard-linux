#ifndef _SG_CONTEXT_H
#define _SG_CONTEXT_H

#include <net/sock.h>
#include <net/tcp.h>

struct sg_context {
	struct proto *tcp_prot;
};

static inline struct sg_context *get_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	/* from include/net/tls.h:
		Use RCU on icsk_ulp_data only for sock diag code,
		TLS data path doesn't need rcu_dereference().
	*/

	return (__force void *)icsk->icsk_ulp_data;
}
struct sg_context *ctx_create(struct sock *sk);

#endif /* _SG_CONTEXT_H */
