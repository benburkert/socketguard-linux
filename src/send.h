#ifndef _SG_SEND_H
#define _SG_SEND_H

int sg_send_handshake_initiation(struct sock *sk, int flags);
int sg_send_handshake_response(struct sock *sk, int flags);
int sg_send_data(struct sock *sk, u8 *data, int len, int flags);

#endif /* _SG_SEND_H */
