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
