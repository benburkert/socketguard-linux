#include "context.h"
#include "messages.h"
#include "noise.h"
#include "proto.h"

int socket_send_buffer(struct sock *sk, void *buffer, size_t len, int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	struct page *p = alloc_page(sk->sk_allocation);
	struct kvec vec = {
		.iov_base = buffer,
		.iov_len = len,
	};
	struct msghdr msg = {};
	int ret;

	if (p == NULL)
		return -ENOMEM;

	iov_iter_kvec(&msg.msg_iter, WRITE, &vec, 1, len);
	ret = copy_page_from_iter(p, 0, len, &msg.msg_iter);
	if (ret < 0)
		goto out;
	if (ret != len) {
		ret = -EFAULT;
		goto out;
	}

        ret = ctx->tcp_prot->sendpage(sk, p, 0, len, flags);
out:
	__free_page(p);
	return ret;
}

int sg_send_handshake_initiation(struct sock *sk, int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sg_message_handshake_initiation packet;
	struct sg_handshake handshake = ctx->handshake;
	int ret;

	handshake_init(&handshake);
	handshake_create_initiation(&packet, &handshake, &ctx->static_identity,
				    &ctx->remote_identity, &ctx->version);

	if (handshake.state != HANDSHAKE_CREATED_INITIATION)
		return -EKEYREJECTED;

	ret = socket_send_buffer(sk, &packet, sizeof(packet), flags);
	if (ret < 0)
		return ret;
	if (ret != sizeof(packet))
		return -EINVAL;

	ctx->handshake = handshake;
	return 0;
}

int sg_send_handshake_response(struct sock *sk, int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sg_message_handshake_response packet;
	struct sg_handshake handshake = ctx->handshake;
	int ret;

	if (handshake.state != HANDSHAKE_CONSUMED_INITIATION)
		return -EINVAL;

	handshake_create_response(&packet, &handshake, &ctx->remote_identity);

	if (handshake.state != HANDSHAKE_CREATED_RESPONSE)
		return -EKEYREJECTED;

	ret = socket_send_buffer(sk, &packet, sizeof(packet), flags);
	if (ret < 0)
		return ret;
	if (ret != sizeof(packet))
		return -EINVAL;


	handshake_begin_session(&handshake, &ctx->keypair);

	ctx->handshake = handshake;
	return 0;
}

int sg_send_handshake_rekey(struct sock *sk, int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	struct sg_noise_keypair keypair = ctx->keypair;
	struct sg_message_handshake_rekey packet;
	int ret;

	if (unlikely(ctx->handshake.state != HANDSHAKE_CREATED_RESPONSE &&
		    ctx->handshake.state != HANDSHAKE_CONSUMED_RESPONSE))
		return -EINVAL;

	if (!handshake_create_rekey(&packet, &ctx->handshake, &keypair,
				    &ctx->remote_identity))
		return -EKEYREJECTED;

	ret = socket_send_buffer(sk, &packet, sizeof(packet), flags);
	if (ret < 0)
		return ret;
	if (ret != sizeof(packet))
		return -EINVAL;

	ctx->keypair = keypair;
	return 0;
}

int sg_send_data(struct sock *sk, u8 *data, int len, int flags)
{
	struct sg_context *ctx = get_ctx(sk);
	int packet_len = sizeof(struct sg_message_header) +
		sg_noise_encrypted_len(len);
	struct sg_message_data *packet;
	int ret;

	if (!ctx->keypair.sending.is_valid)
		return -EINVAL;

	packet = kzalloc(packet_len, sk->sk_allocation);
	message_data_encrypt(packet, &ctx->keypair, data, len);
	ret = socket_send_buffer(sk, packet, packet_len, flags);
	if (ret > 0)
		ctx->keypair.sending.counter++;

	kzfree(packet);
	return ret;
}
