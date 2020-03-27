#ifndef _SG_MESSAGES_H
#define _SG_MESSAGES_H

#include <crypto/blake2s.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/curve25519.h>
#include <linux/types.h>


enum sg_noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
	NOISE_TIMESTAMP_LEN = sizeof(u64) + sizeof(u32),
	NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAG_SIZE,
	NOISE_HASH_LEN = BLAKE2S_HASH_SIZE,
};

#define sg_noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

enum sg_limits {
	GRANULARITY_PER_SECOND = 50,
};

enum sg_message_type {
	MESSAGE_INVALID = 0,
	MESSAGE_HANDSHAKE_INITIATION = 1,
	MESSAGE_HANDSHAKE_RESPONSE = 2,
	MESSAGE_DATA = 4,
};

struct sg_message_header {
	/* The actual layout of this that we want is:
	 * u8 type
	 * u8 reserved_zero[3]
	 *
	 * But it turns out that by encoding this as little endian,
	 * we achieve the same thing, and it makes checking faster.
	 */
	__le32 type;
};

struct sg_message_handshake_initiation {
	struct sg_message_header header;
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_static[sg_noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
	u8 encrypted_timestamp[sg_noise_encrypted_len(NOISE_TIMESTAMP_LEN)];
};

struct sg_message_handshake_response {
	struct sg_message_header header;
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_nothing[sg_noise_encrypted_len(0)];
};

struct sg_message_data {
	struct sg_message_header header;
	__le32 len;
	u8 encrypted_data[];
};

#define sg_message_data_len(plain_len) \
	(sg_noise_encrypted_len(plain_len) + sizeof(struct sg_message_data))

#endif /* _SG_MESSAGES_H */
