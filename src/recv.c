#include "context.h"
#include "messages.h"
#include "noise.h"

int socket_recv_buffer(struct sock *sk, void *buffer, size_t len, int nonblock,
		       int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	struct msghdr msg = {};
	struct kvec vec = {
		.iov_base = buffer,
		.iov_len = len,
	};
	int addr_len, ret;

	iov_iter_kvec(&msg.msg_iter, READ, &vec, 1, len);
	ret = ctx->tcp_prot->recvmsg(sk, &msg, len, nonblock, flags, &addr_len);
	if (ret < 0)
		return ret;
	if (ret != len)
		return -EINVAL;
	return 0;
}

int sg_recv_handshake_initiation(struct sock *sk, int nonblock, int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sg_message_handshake_initiation packet;
	int err;

	if (ctx->handshake.state != HANDSHAKE_ZEROED)
		return -EINVAL;
	err = socket_recv_buffer(sk, &packet, sizeof(packet), nonblock, flags);
	if (err)
		return err;
	if (packet.header.type != cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION))
		return -EINVAL;

	handshake_clear(&ctx->handshake);
	handshake_consume_initiation(&packet, &ctx->handshake,
				     &ctx->static_identity,
				     &ctx->remote_identity);

        if (ctx->handshake.state != HANDSHAKE_CONSUMED_INITIATION) {
		return -EKEYREJECTED;
	}

	return 0;
}

int sg_recv_handshake_response(struct sock *sk, int nonblock, int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sg_message_handshake_response packet;
	int err;

	if (ctx->handshake.state != HANDSHAKE_CREATED_INITIATION)
		return -EINVAL;
	err = socket_recv_buffer(sk, &packet, sizeof(packet), nonblock, flags);
	if (err)
		return err;
	if (packet.header.type != cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE))
		return -EINVAL;

	handshake_consume_response(&packet, &ctx->handshake,
				   &ctx->static_identity,
				   &ctx->remote_identity);

	if (ctx->handshake.state != HANDSHAKE_CONSUMED_RESPONSE)
		return -EKEYREJECTED;
	return 0;
}
