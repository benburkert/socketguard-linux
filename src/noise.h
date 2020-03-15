#ifndef _SG_NOISE_H
#define _SG_NOISE_H

#include "messages.h"
#include "uapi/socketguard.h"

struct sg_remote_identity {
	u8 remote_static[NOISE_PUBLIC_KEY_LEN];
	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	bool has_identity;
};

struct sg_static_identity {
	u8 static_public[NOISE_PUBLIC_KEY_LEN];
	u8 static_private[NOISE_PUBLIC_KEY_LEN];
	bool has_identity;
};

enum sg_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
};

struct sg_handshake {
	enum sg_handshake_state state;

	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 precomputed_static_static[NOISE_PUBLIC_KEY_LEN];

	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
};

void noise_init(void);

void remote_identity_init(struct sg_remote_identity *remote_identity,
			  const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			  const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN]);
void static_identity_init(struct sg_static_identity *static_identity,
			  const u8 private_key[NOISE_PUBLIC_KEY_LEN]);

void handshake_clear(struct sg_handshake *handshake);
void handshake_create_initiation(struct sg_message_handshake_initiation *dst,
				 struct sg_handshake *handshake,
				 struct sg_static_identity *static_identity,
				 struct sg_remote_identity *remote_identity);

#endif /* _SG_NOISE_H */
