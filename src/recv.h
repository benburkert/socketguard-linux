#include <net/sock.h>

#ifndef _SG_RECV_H
#define _SG_RECV_H

int sg_peek_header(struct sock *sk, struct sg_message_header *hdr, int nonblock,
		   int flags);
int sg_recv_data(struct sock *sk, u8 **data, int nonblock, int flags);
int sg_recv_handshake_initiation(struct sock *sk, int nonblock, int flags);
int sg_recv_handshake_response(struct sock *sk, int nonblock, int flags);
int sg_recv_handshake_rekey(struct sock *sk, int nonblock, int flags);

#endif /* _SG_RECV_H */
