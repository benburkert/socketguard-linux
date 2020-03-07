#include "context.h"
#include "proto.h"

#include <net/sock.h>

struct sg_context *ctx_create(struct sock *sk)
{
	struct sg_context *ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return NULL;
	ctx->tcp_prot = get_tcp_proto(sk);
	return ctx;
}

void ctx_copy_public_info(struct sg_context *ctx,
			  struct sg_crypto_info *crypto_info)
{
	memcpy(crypto_info->static_public, ctx->static_identity.static_public,
	       NOISE_PUBLIC_KEY_LEN);
	memcpy(crypto_info->peer_public, ctx->remote_identity.remote_static,
	       NOISE_PUBLIC_KEY_LEN);
}

void ctx_set_crypto_info(struct sg_context *ctx,
			 struct sg_crypto_info *crypto_info)
{
	remote_identity_init(&ctx->remote_identity, crypto_info->peer_public,
			     crypto_info->preshared_key);
	static_identity_init(&ctx->static_identity,
			     crypto_info->static_private);
}
