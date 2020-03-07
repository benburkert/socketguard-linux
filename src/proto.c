#include "context.h"

#include <linux/highmem.h>
#include <net/sock.h>

static struct proto sg_prots[2] = {0};
static struct proto *tcp_prots[2] = {NULL};
static DEFINE_MUTEX(saved_prot_mutex);

#define PROT_INET_IDX(sk) (sk->sk_family == AF_INET ? 0 : 1)

void init_protos(struct sock *sk)
{
	int idx = PROT_INET_IDX(sk);
	struct proto *sg_prot, *tcp_prot;

	if (likely(smp_load_acquire(&tcp_prots[idx]) != NULL))
		return;

	mutex_lock(&saved_prot_mutex);
	if (likely((tcp_prot = tcp_prots[idx]) == NULL)) {
		tcp_prot = sk->sk_prot;

		sg_prot = &sg_prots[idx];
		*sg_prot = *tcp_prot;
		// TODO: set sg_prot->(...) = sg_(...)

		smp_store_release(&tcp_prots[idx], tcp_prot);
	}
	mutex_unlock(&saved_prot_mutex);
}

struct proto *get_tcp_proto(struct sock *sk)
{
	return smp_load_acquire(&tcp_prots[PROT_INET_IDX(sk)]);
}

struct proto *get_sg_proto(struct sock *sk)
{
	return &sg_prots[PROT_INET_IDX(sk)];
}

#undef PROT_INET_IDX
