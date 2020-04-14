#include "context.h"
#include "proto.h"

#include <net/sock.h>

static const struct sg_version default_version = {
	.min = cpu_to_le16(SG_VERSION),
	.max = cpu_to_le16(SG_VERSION),
};

struct sg_context *ctx_create(struct sock *sk, const gfp_t priority)
{
	struct sg_context *ctx = kzalloc(sizeof(*ctx), priority);
	if (!ctx)
		return NULL;
	ctx->tcp_prot = get_tcp_proto(sk);
	memcpy(&ctx->version, &default_version, sizeof(ctx->version));
	return ctx;
}

void ctx_copy_public_info(struct sg_context *ctx,
			  struct sg_crypto_info *crypto_info)
{
	crypto_info->min_version = le16_to_cpu(ctx->version.min);
	crypto_info->max_version = le16_to_cpu(ctx->version.max);

	memcpy(crypto_info->static_public, ctx->static_identity.static_public,
	       NOISE_PUBLIC_KEY_LEN);
	memcpy(crypto_info->peer_public, ctx->remote_identity.remote_static,
	       NOISE_PUBLIC_KEY_LEN);
}

void ctx_set_crypto_info(struct sg_context *ctx,
			 struct sg_crypto_info *crypto_info)
{
	if (crypto_info->min_version)
		ctx->version.min = cpu_to_le16(crypto_info->min_version);
	if (crypto_info->max_version)
		ctx->version.max = cpu_to_le16(crypto_info->max_version);

	remote_identity_init(&ctx->remote_identity, crypto_info->peer_public,
			     crypto_info->preshared_key);
	static_identity_init(&ctx->static_identity,
			     crypto_info->static_private);
}
