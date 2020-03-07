#ifndef _SG_NOISE_H
#define _SG_NOISE_H

#include "uapi/socketguard.h"

#include <crypto/curve25519.h>
#include <crypto/chacha20poly1305.h>
#include <linux/types.h>

enum sg_noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
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

void remote_identity_init(struct sg_remote_identity *remote_identity,
			  const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			  const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN]);
void static_identity_init(struct sg_static_identity *static_identity,
			  const u8 private_key[NOISE_PUBLIC_KEY_LEN]);

#endif /* _SG_NOISE_H */
