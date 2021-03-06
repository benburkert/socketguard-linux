#include "context.h"
#include "proto.h"
#include "recv.h"
#include "send.h"
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
	memcpy(&newctx->version, &oldctx->version, sizeof(newctx->version));
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
		sg_prot->connect    = sg_connect;
		sg_prot->getsockopt = sg_getsockopt;
		sg_prot->setsockopt = sg_setsockopt;
		sg_prot->recvmsg    = sg_recvmsg;
		sg_prot->sendmsg    = sg_sendmsg;

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

		if (crypto_info.min_version != SG_VERSION ||
		    crypto_info.max_version != SG_VERSION ||
		    crypto_info.min_version > crypto_info.max_version)
			return -EINVAL;

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

int sg_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sg_context *ctx = get_ctx(sk);
	int flags;
	int err;

	if (!ctx->static_identity.has_identity ||
	    !ctx->remote_identity.has_identity)
		return -ENOKEY;


	// TODO: support TFO

	err = ctx->tcp_prot->connect(sk, uaddr, addr_len);
	if (err)
		return err;

	// TODO: better way to check if O_NONBLOCK is set?
	flags = (sk->sk_socket->file->f_flags&SOCK_NONBLOCK) ? MSG_DONTWAIT : 0;

	// TODO: release_sock is a workaround to avoid deadlock b/c send grabs
	//       sock's lock.
	release_sock(sk);

	err = sg_send_handshake_initiation(sk, flags);
	lock_sock(sk);

	return err;
}

static inline bool sg_handshake_finished(struct sg_handshake handshake)
{
	return likely(handshake.state == HANDSHAKE_CREATED_RESPONSE ||
		      handshake.state == HANDSHAKE_CONSUMED_RESPONSE);
}

static inline bool sg_sending_key_expired(struct sg_noise_keypair keypair)
{
	return symmetric_key_expired(keypair.sending, REKEY_AFTER_TIME);
}

static inline bool sg_receiving_key_expired(struct sg_noise_keypair keypair)
{
	return symmetric_key_expired(keypair.receiving, REJECT_AFTER_TIME);
}

static int sg_do_handshake(struct sock *sk, int nonblock, int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	int err;

	switch (ctx->handshake.state) {
	case HANDSHAKE_ZEROED:
		err = sg_recv_handshake_initiation(sk, nonblock, flags);
		if (err) {
			// TODO: close early
			return err;
		}

		return sg_send_handshake_response(sk, nonblock|flags);
	case HANDSHAKE_CREATED_INITIATION:
		err = sg_recv_handshake_response(sk, nonblock, flags);
		if (err) {
			// TODO: close early
			return err;
		}
		return 0;
	default:
		return -EINVAL;
	}
}

static int sg_do_rekey(struct sock *sk, int nonblock, int flags)
{
	return sg_send_handshake_rekey(sk, nonblock|flags);
}

int sg_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int nonblock,
	       int flags, int *addr_len)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sg_message_header hdr;
	u8 *data;
	int ret, err;

	if (!sg_handshake_finished(ctx->handshake)) {
		err = sg_do_handshake(sk, nonblock, flags);
		if (err)
			return err;
	}

	for (;;) {
		memset(&hdr, 0, sizeof(hdr));
		err = sg_peek_header(sk, &hdr, nonblock, flags);
		if (err )
			return err;

		switch (hdr.type) {
		case cpu_to_le32(MESSAGE_HANDSHAKE_REKEY):
			if (!sg_header_len_valid(hdr, sg_message_handshake_rekey))
				return -EINVAL;

			ret = sg_recv_handshake_rekey(sk, nonblock, flags);
			if (ret < 0)
				return ret;
			break;
		case cpu_to_le32(MESSAGE_DATA):
			if (sg_receiving_key_expired(ctx->keypair)) {
				return -EKEYREJECTED;
			}

			ret = sg_recv_data(sk, &data, le32_to_cpu(hdr.len),
					   nonblock, flags);
			if (ret <= 0)
				return ret;

			ret = copy_to_iter(data, ret, &msg->msg_iter);
			kzfree(data);
			return ret;
		default:
			return -EINVAL;
		}
	}
}

int sg_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct sg_context *ctx = get_ctx(sk);
	int nonblock = msg->msg_flags&MSG_DONTWAIT;
	int err = 0;
	u8 *buf;
	size_t len;

	if (!sg_handshake_finished(ctx->handshake)) {
		err = sg_do_handshake(sk, nonblock, msg->msg_flags);
	} else if (sg_sending_key_expired(ctx->keypair)) {
		err = sg_do_rekey(sk, nonblock, msg->msg_flags);
	}
	if (err)
		return err;

	len = msg->msg_iter.count;
        buf = kzalloc(len, sk->sk_allocation);
	copy_from_iter(buf, len, &msg->msg_iter);

	err = sg_send_data(sk, buf, (int)len, msg->msg_flags);
	kzfree(buf);
	return err < 0 ? err : len;
}
