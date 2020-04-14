#ifndef _SG_CONTEXT_H
#define _SG_CONTEXT_H

#include "noise.h"
#include "uapi/socketguard.h"

#include <net/sock.h>
#include <net/tcp.h>

struct sg_context {
	struct proto *tcp_prot;

	struct sg_version version;

	struct sg_static_identity static_identity;
	struct sg_remote_identity remote_identity;

	struct sg_handshake handshake;

	struct sg_noise_keypair keypair; // TODO: switch to list of keypairs
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
static inline void ctx_free(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	struct sg_context *ctx = (__force void *)icsk->icsk_ulp_data;
	if (!ctx)
		return;

	memzero_explicit(ctx->static_identity.static_private,
			 NOISE_PUBLIC_KEY_LEN);
	memzero_explicit(ctx->remote_identity.preshared_key,
			 NOISE_SYMMETRIC_KEY_LEN);

	rcu_assign_pointer(icsk->icsk_ulp_data, NULL);
        kfree(ctx);
}
struct sg_context *ctx_create(struct sock *sk, const gfp_t priority);

void ctx_copy_public_info(struct sg_context *ctx,
			  struct sg_crypto_info *crypto_info);
void ctx_set_crypto_info(struct sg_context *ctx,
			 struct sg_crypto_info *crypto_info);

#endif /* _SG_CONTEXT_H */
