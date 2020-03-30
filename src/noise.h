#ifndef _SG_NOISE_H
#define _SG_NOISE_H

#include "messages.h"
#include "uapi/socketguard.h"

struct sg_noise_symmetric_key {
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u64 counter;
	u64 birthdate;
	bool is_valid;
};

struct sg_noise_keypair {
	struct sg_noise_symmetric_key sending;
	struct sg_noise_symmetric_key receiving;
};

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
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE,
};

struct sg_handshake {
	enum sg_handshake_state state;

	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];

	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];

	u8 latest_timestamp[NOISE_TIMESTAMP_LEN];
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
void handshake_consume_initiation(struct sg_message_handshake_initiation *src,
				  struct sg_handshake *handshake,
				  struct sg_static_identity *static_identity,
				  struct sg_remote_identity *remote_identity);
void handshake_create_response(struct sg_message_handshake_response *dst,
			       struct sg_handshake *handshake,
			       struct sg_static_identity *static_identity,
			       struct sg_remote_identity *remote_identity);
void handshake_consume_response(struct sg_message_handshake_response *src,
				struct sg_handshake *handshake,
				struct sg_static_identity *static_identity,
				struct sg_remote_identity *remote_identity);
void handshake_begin_session(struct sg_handshake *handshake,
			     struct sg_noise_keypair *keypair);

void message_data_encrypt(struct sg_message_data *message,
			  struct sg_noise_keypair *keypair, u8 *data, int len);
bool message_data_decrypt(struct sg_message_data *message,
			  struct sg_noise_keypair *keypair, u8 *data, int len);

#endif /* _SG_NOISE_H */
