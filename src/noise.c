#include "noise.h"

#include <linux/types.h>

void remote_identity_init(struct sg_remote_identity *remote_identity,
			  const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			  const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
	u8 empty[NOISE_PUBLIC_KEY_LEN] = { 0 };

	memcpy(remote_identity->remote_static, public_key,
	       NOISE_PUBLIC_KEY_LEN);
	remote_identity->has_identity =
		curve25519(empty, empty, remote_identity->remote_static);
	memcpy(remote_identity->preshared_key, preshared_key,
	       NOISE_SYMMETRIC_KEY_LEN);
}

void static_identity_init(struct sg_static_identity *static_identity,
			  const u8 private_key[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(static_identity->static_private, private_key,
	       NOISE_PUBLIC_KEY_LEN);
	curve25519_clamp_secret(static_identity->static_private);
	static_identity->has_identity =
		curve25519_generate_public(static_identity->static_public,
					   private_key);
}
