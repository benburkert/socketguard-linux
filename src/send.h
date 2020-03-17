#ifndef _SG_SEND_H
#define _SG_SEND_H

int sg_send_handshake_initiation(struct sock *sk);
int sg_send_handshake_response(struct sock *sk);

#endif /* _SG_SEND_H */
