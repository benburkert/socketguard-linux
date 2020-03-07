#include "context.h"
#include "proto.h"
#include "uapi/socketguard.h"

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
		sg_prot->getsockopt = sg_getsockopt;
		sg_prot->setsockopt = sg_setsockopt;
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

int sg_getsockopt(struct sock *sk, int level, int optname, char __user *optval,
		  int __user *optlen)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sg_crypto_info crypto_info;

	if (level != SOL_SOCKETGUARD)
		return ctx->tcp_prot->getsockopt(sk, level, optname, optval,
						 optlen);
	switch(optname) {
	case SG_CRYPTO_INFO:
		ctx_copy_public_info(ctx, &crypto_info);
		if (copy_to_user(optval, &crypto_info, sizeof(crypto_info)))
			return -EFAULT;
		return 0;
	default:
		return -ENOPROTOOPT;
	}
}

int sg_setsockopt(struct sock *sk, int level, int optname, char __user *optval,
		  unsigned int optlen)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sg_crypto_info crypto_info;
	int err;

	if (level != SOL_SOCKETGUARD)
		return ctx->tcp_prot->setsockopt(sk, level, optname, optval,
						 optlen);

	switch(optname) {
	case SG_CRYPTO_INFO:
		if (!optval || (optlen < sizeof(crypto_info)))
			return -EINVAL;

		err = copy_from_user(&crypto_info, optval, sizeof(crypto_info));
		if (err) {
			memzero_explicit(&crypto_info, sizeof(crypto_info));
			return -EFAULT;
		}

		// TODO: lock_sock(sk)?
		ctx_set_crypto_info(ctx, &crypto_info);
		return 0;
	default:
		return -ENOPROTOOPT;
	}
}
