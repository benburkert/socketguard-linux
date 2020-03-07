#include "context.h"
#include "proto.h"
#include "uapi/socketguard.h"

#include <linux/highmem.h>
#include <linux/tcp.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include <net/tcp.h>

// lock_sock(sk) held
int ulp_init(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct proto *sg_prot;
	struct sg_context *ctx;

	init_protos(sk);
	sg_prot = get_sg_proto(sk);

	ctx = ctx_create(sk, GFP_ATOMIC);
	if (!ctx)
		return -ENOMEM;

	write_lock_bh(&sk->sk_callback_lock);
	rcu_assign_pointer(icsk->icsk_ulp_data, ctx);
	sk->sk_prot = sg_prot;
	write_unlock_bh(&sk->sk_callback_lock);

	return 0;
}

void ulp_clone(const struct request_sock *req, struct sock *newsk,
	      const gfp_t priority)
{
	struct inet_connection_sock *icsk = inet_csk(newsk);
	struct proto *sg_prot = get_sg_proto(newsk);
	struct sg_context *oldctx = get_ctx(newsk);

	struct sg_context *newctx = ctx_create(newsk, priority);
	if (newctx == NULL)
		return;

	// TODO: lock old sock via lock_sock(newsk)?
	memcpy(&newctx->static_identity, &oldctx->static_identity,
	       sizeof(newctx->static_identity));
	memcpy(&newctx->remote_identity, &oldctx->remote_identity,
	       sizeof(newctx->remote_identity));

	write_lock_bh(&newsk->sk_callback_lock);
	rcu_assign_pointer(icsk->icsk_ulp_data, newctx);
	rcu_assign_pointer(icsk->icsk_ulp_ops, NULL); // TODO: workaround b/c tcp_set_ulp is not exported
	newsk->sk_prot = sg_prot;
	write_unlock_bh(&newsk->sk_callback_lock);
}

void ulp_release(struct sock *sk)
{
	ctx_free(sk);
}

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
		sg_prot->accept     = sg_accept;
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

		lock_sock(sk);
		ctx_set_crypto_info(ctx, &crypto_info);
		release_sock(sk);

		return 0;
	default:
		return -ENOPROTOOPT;
	}
}

struct sock *sg_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sock *newsk;

	// TODO: support TFO
	newsk = ctx->tcp_prot->accept(sk, flags, err, kern);
	if (!newsk)
		return newsk;
	if (!get_ctx(newsk))
		*err = -ENOMEM;
	return newsk;
}
