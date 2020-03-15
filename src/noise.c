#include "messages.h"
#include "noise.h"

#include <linux/types.h>

/* This implements Noise_IKpsk2:
 *
 * <- s
 * ******
 * -> e, es, s, ss, {t}
 * <- e, ee, se, psk, {}
 */

static const u8 handshake_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const u8 identifier_name[14] = "SocketGuard v1";
static u8 handshake_init_hash[NOISE_HASH_LEN] __ro_after_init;
static u8 handshake_init_chaining_key[NOISE_HASH_LEN] __ro_after_init;

void __init noise_init(void)
{
	struct blake2s_state blake;

	blake2s(handshake_init_chaining_key, handshake_name, NULL,
		NOISE_HASH_LEN, sizeof(handshake_name), 0);
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
	blake2s_update(&blake, identifier_name, sizeof(identifier_name));
	blake2s_final(&blake, handshake_init_hash);
}

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

/* This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869
 */
static void kdf(u8 *first_dst, u8 *second_dst, u8 *third_dst, const u8 *data,
		size_t first_len, size_t second_len, size_t third_len,
		size_t data_len, const u8 chaining_key[NOISE_HASH_LEN])
{
	u8 output[BLAKE2S_HASH_SIZE + 1];
	u8 secret[BLAKE2S_HASH_SIZE];

	WARN_ON(IS_ENABLED(DEBUG) &&
		(first_len > BLAKE2S_HASH_SIZE ||
		 second_len > BLAKE2S_HASH_SIZE ||
		 third_len > BLAKE2S_HASH_SIZE ||
		 ((second_len || second_dst || third_len || third_dst) &&
		  (!first_len || !first_dst)) ||
		 ((third_len || third_dst) && (!second_len || !second_dst))));

	/* Extract entropy from data into secret */
	blake2s256_hmac(secret, data, chaining_key, data_len, NOISE_HASH_LEN);

	if (!first_dst || !first_len)
		goto out;

	/* Expand first key: key = secret, data = 0x1 */
	output[0] = 1;
	blake2s256_hmac(output, output, secret, 1, BLAKE2S_HASH_SIZE);
	memcpy(first_dst, output, first_len);

	if (!second_dst || !second_len)
		goto out;

	/* Expand second key: key = secret, data = first-key || 0x2 */
	output[BLAKE2S_HASH_SIZE] = 2;
	blake2s256_hmac(output, output, secret, BLAKE2S_HASH_SIZE + 1,
			BLAKE2S_HASH_SIZE);
	memcpy(second_dst, output, second_len);

	if (!third_dst || !third_len)
		goto out;

	/* Expand third key: key = secret, data = second-key || 0x3 */
	output[BLAKE2S_HASH_SIZE] = 3;
	blake2s256_hmac(output, output, secret, BLAKE2S_HASH_SIZE + 1,
			BLAKE2S_HASH_SIZE);
	memcpy(third_dst, output, third_len);

out:
	/* Clear sensitive data from stack */
	memzero_explicit(secret, BLAKE2S_HASH_SIZE);
	memzero_explicit(output, BLAKE2S_HASH_SIZE + 1);
}

static bool __must_check mix_dh(u8 chaining_key[NOISE_HASH_LEN],
				u8 key[NOISE_SYMMETRIC_KEY_LEN],
				const u8 private[NOISE_PUBLIC_KEY_LEN],
				const u8 public[NOISE_PUBLIC_KEY_LEN])
{
	u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];

	if (unlikely(!curve25519(dh_calculation, private, public)))
		return false;
	kdf(chaining_key, key, NULL, dh_calculation, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);
	memzero_explicit(dh_calculation, NOISE_PUBLIC_KEY_LEN);
	return true;
}

static void mix_hash(u8 hash[NOISE_HASH_LEN], const u8 *src, size_t src_len)
{
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash);
}

static void message_ephemeral(u8 ephemeral_dst[NOISE_PUBLIC_KEY_LEN],
			      const u8 ephemeral_src[NOISE_PUBLIC_KEY_LEN],
			      u8 chaining_key[NOISE_HASH_LEN],
			      u8 hash[NOISE_HASH_LEN])
{
	if (ephemeral_dst != ephemeral_src)
		memcpy(ephemeral_dst, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	mix_hash(hash, ephemeral_src, NOISE_PUBLIC_KEY_LEN);
	kdf(chaining_key, NULL, NULL, ephemeral_src, NOISE_HASH_LEN, 0, 0,
	    NOISE_PUBLIC_KEY_LEN, chaining_key);
}


void handshake_clear(struct sg_handshake *handshake)
{
	memset(&handshake->ephemeral_private, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->remote_ephemeral, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->hash, 0, NOISE_HASH_LEN);
	memset(&handshake->chaining_key, 0, NOISE_HASH_LEN);
	handshake->state = HANDSHAKE_ZEROED;
}

static void handshake_init(u8 chaining_key[NOISE_HASH_LEN],
			   u8 hash[NOISE_HASH_LEN],
			   const u8 remote_static[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	mix_hash(hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static void message_encrypt(u8 *dst_ciphertext, const u8 *src_plaintext,
			    size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
			    u8 hash[NOISE_HASH_LEN])
{
	chacha20poly1305_encrypt(dst_ciphertext, src_plaintext, src_len, hash,
				 NOISE_HASH_LEN,
				 0 /* Always zero for Noise_IK */, key);
	mix_hash(hash, dst_ciphertext, sg_noise_encrypted_len(src_len));
}

static void tai64n_now(u8 output[NOISE_TIMESTAMP_LEN])
{
	struct timespec64 now;

	ktime_get_real_ts64(&now);

	/* In order to prevent some sort of infoleak from precise timers, we
	 * round down the nanoseconds part to the closest rounded-down power of
	 * two to the maximum initiations per second allowed anyway by the
	 * implementation.
	 */
	now.tv_nsec = ALIGN_DOWN(now.tv_nsec,
		rounddown_pow_of_two(NSEC_PER_SEC / INITIATIONS_PER_SECOND));

	/* https://cr.yp.to/libtai/tai64.html */
	*(__be64 *)output = cpu_to_be64(0x400000000000000aULL + now.tv_sec);
	*(__be32 *)(output + sizeof(__be64)) = cpu_to_be32(now.tv_nsec);
}

void handshake_create_initiation(struct sg_message_handshake_initiation *dst,
				 struct sg_handshake *handshake,
				 struct sg_static_identity *static_identity,
				 struct sg_remote_identity *remote_identity)
{
	u8 timestamp[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];

	/* We need to wait for crng _before_ taking any locks, since
	 * curve25519_generate_secret uses get_random_bytes_wait.
	 */
	wait_for_random_bytes();

	// TODO: already checked *_identity->has_identity in connect()

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);
	handshake_init(handshake->chaining_key, handshake->hash,
		       remote_identity->remote_static);

	/* e */
	curve25519_generate_secret(handshake->ephemeral_private);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral,
					handshake->ephemeral_private))
		goto out;
	message_ephemeral(dst->unencrypted_ephemeral,
			  dst->unencrypted_ephemeral, handshake->chaining_key,
			  handshake->hash);

	/* es */
	if (!mix_dh(handshake->chaining_key, key, handshake->ephemeral_private,
		    remote_identity->remote_static))
		goto out;

	/* s */
	message_encrypt(dst->encrypted_static, static_identity->static_public,
			NOISE_PUBLIC_KEY_LEN, key, handshake->hash);

	/* ss */
	kdf(handshake->chaining_key, key, NULL,
	    handshake->precomputed_static_static, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN,
	    handshake->chaining_key);

	/* {t} */
	tai64n_now(timestamp);
	message_encrypt(dst->encrypted_timestamp, timestamp,
			NOISE_TIMESTAMP_LEN, key, handshake->hash);

	handshake->state = HANDSHAKE_CREATED_INITIATION;
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
}
