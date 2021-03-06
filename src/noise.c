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

static void symmetric_key_init(struct sg_noise_symmetric_key *key)
{
	key->counter = 0;
	key->birthdate = ktime_get_coarse_boottime_ns();
	key->is_valid = true;
}

static void derive_key(struct sg_noise_symmetric_key *dst, const u8
		       chaining_key[NOISE_HASH_LEN])
{
	kdf(dst->key, NULL, NULL, NULL, NOISE_SYMMETRIC_KEY_LEN, 0, 0, 0,
	    chaining_key);
	symmetric_key_init(dst);
}

static void derive_keys(struct sg_noise_symmetric_key *first_dst,
			struct sg_noise_symmetric_key *second_dst,
			const u8 chaining_key[NOISE_HASH_LEN])
{
	kdf(first_dst->key, second_dst->key, NULL, NULL,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
	    chaining_key);
	symmetric_key_init(first_dst);
	symmetric_key_init(second_dst);
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

static void mix_psk(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN],
		    u8 key[NOISE_SYMMETRIC_KEY_LEN],
		    const u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	u8 temp_hash[NOISE_HASH_LEN];

	kdf(chaining_key, temp_hash, key, psk, NOISE_HASH_LEN, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	mix_hash(hash, temp_hash, NOISE_HASH_LEN);
	memzero_explicit(temp_hash, NOISE_HASH_LEN);
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

static u64 now(void)
{
	return ALIGN_DOWN(ktime_get_coarse_boottime_ns(),
			  rounddown_pow_of_two(NSEC_PER_MSEC));
}

static void timestamp_now(u8 timestamp[NOISE_TIMESTAMP_LEN], u64 epoch)
{
	__le64 t = cpu_to_le64(now() - epoch);
	memcpy(timestamp, &t, NOISE_TIMESTAMP_LEN);
}

void handshake_init(struct sg_handshake *handshake)
{
	memset(&handshake->ephemeral_private, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->remote_ephemeral, 0, NOISE_PUBLIC_KEY_LEN);
	memset(&handshake->hash, 0, NOISE_HASH_LEN);
	memset(&handshake->chaining_key, 0, NOISE_HASH_LEN);
	handshake->epoch = now();
	handshake->state = HANDSHAKE_ZEROED;
}

static void handshake_reset(u8 chaining_key[NOISE_HASH_LEN],
			    u8 hash[NOISE_HASH_LEN],
			    const u8 remote_static[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN);
	mix_hash(hash, remote_static, NOISE_PUBLIC_KEY_LEN);
}

static void rekey_reset(u8 hash[NOISE_HASH_LEN],
			const u8 remote_static[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
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

static bool message_decrypt(u8 *dst_plaintext, const u8 *src_ciphertext,
			    size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN],
			    u8 hash[NOISE_HASH_LEN])
{
	if (!chacha20poly1305_decrypt(dst_plaintext, src_ciphertext, src_len,
				      hash, NOISE_HASH_LEN,
				      0 /* Always zero for Noise_IK */, key))
		return false;
	mix_hash(hash, src_ciphertext, src_len);
	return true;
}

bool symmetric_key_expired(struct sg_noise_symmetric_key key,
			   u64 expiration_seconds)
{
	// TODO: max counter check

	return (s64)(key.birthdate + expiration_seconds * NSEC_PER_SEC)
		<= (s64)ktime_get_coarse_boottime_ns();
}

void handshake_create_initiation(struct sg_message_handshake_initiation *dst,
				 struct sg_handshake *handshake,
				 struct sg_static_identity *static_identity,
				 struct sg_remote_identity *remote_identity,
				 struct sg_version *version)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];

	if (unlikely(!static_identity->has_identity ||
		     !remote_identity->has_identity))
		return;

	/* We need to wait for crng _before_ taking any locks, since
	 * curve25519_generate_secret uses get_random_bytes_wait.
	 */
	wait_for_random_bytes();

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);
	dst->header.len = cpu_to_le32(sg_message_len(*dst));
	handshake_reset(handshake->chaining_key, handshake->hash,
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

	/* version */
	message_encrypt(dst->encrypted_version, (u8*)version, NOISE_VERSION_LEN,
			key, handshake->hash);
	kdf(handshake->chaining_key, key, NULL, (u8*)version, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_VERSION_LEN,
	    handshake->chaining_key);

	/* s */
	message_encrypt(dst->encrypted_static, static_identity->static_public,
			NOISE_PUBLIC_KEY_LEN, key, handshake->hash);

	/* ss */
	if (!curve25519(handshake->static_static,
			static_identity->static_private,
			remote_identity->remote_static))
		goto out;
	kdf(handshake->chaining_key, key, NULL, handshake->static_static,
	    NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN,
	    handshake->chaining_key);

	handshake->state = HANDSHAKE_CREATED_INITIATION;
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
}

void handshake_consume_initiation(struct sg_message_handshake_initiation *src,
				  struct sg_handshake *handshake,
				  struct sg_static_identity *static_identity,
				  struct sg_remote_identity *remote_identity)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 s[NOISE_PUBLIC_KEY_LEN];
	u8 ss[NOISE_PUBLIC_KEY_LEN];
	u8 v[NOISE_VERSION_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];

	if (unlikely(!static_identity->has_identity))
		return;

	handshake_reset(chaining_key, hash, static_identity->static_public);

	/* e */
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

	/* es */
	if (!mix_dh(chaining_key, key, static_identity->static_private, e))
		goto out;

	/* version */
	if (!message_decrypt(v, src->encrypted_version,
			     sizeof(src->encrypted_version), key, hash))
		goto out;
	kdf(chaining_key, key, NULL, v, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN,
	    0, NOISE_VERSION_LEN, chaining_key);

	/* s */
	if (!message_decrypt(s, src->encrypted_static,
			     sizeof(src->encrypted_static), key, hash))
		goto out;

	if (remote_identity->has_identity &&
	    memcmp(remote_identity->remote_static, s, NOISE_PUBLIC_KEY_LEN))
		goto out;

	/* ss */
	if (!curve25519(ss, static_identity->static_private, s))
		goto out;
	kdf(chaining_key, key, NULL, ss, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);

	/* Success! Copy everything to handshake */
	memcpy(remote_identity->remote_static, s, NOISE_PUBLIC_KEY_LEN);
	memcpy(&handshake->version, v, NOISE_VERSION_LEN);
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	memcpy(handshake->static_static, ss, NOISE_PUBLIC_KEY_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	handshake->state = HANDSHAKE_CONSUMED_INITIATION;
out:
	memzero_explicit(ss, NOISE_PUBLIC_KEY_LEN);
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
}

void handshake_create_response(struct sg_message_handshake_response *dst,
			       struct sg_handshake *handshake,
			       struct sg_remote_identity *remote_identity)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];

	/* We need to wait for crng _before_ taking any locks, since
	 * curve25519_generate_secret uses get_random_bytes_wait.
	 */
	wait_for_random_bytes();

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE);
	dst->header.len = cpu_to_le32(sg_message_len(*dst));

	/* e */
	curve25519_generate_secret(handshake->ephemeral_private);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral,
					handshake->ephemeral_private))
		return;
	message_ephemeral(dst->unencrypted_ephemeral,
			  dst->unencrypted_ephemeral, handshake->chaining_key,
			  handshake->hash);

	/* ee */
	if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
		    handshake->remote_ephemeral))
		return;

	/* se */
	if (!mix_dh(handshake->chaining_key, NULL, handshake->ephemeral_private,
		    remote_identity->remote_static))
		return;

	/* psk */
	mix_psk(handshake->chaining_key, handshake->hash, key,
		remote_identity->preshared_key);

	/* version */
	message_encrypt(dst->encrypted_version, (u8*)(&handshake->version),
			NOISE_VERSION_LEN, key, handshake->hash);
	kdf(handshake->chaining_key, NULL, NULL, (u8*)(&handshake->version),
	    NOISE_HASH_LEN, 0, 0, NOISE_VERSION_LEN, handshake->chaining_key);

	memcpy(handshake->send_rekey, handshake->chaining_key, NOISE_HASH_LEN);
	memcpy(handshake->recv_rekey, handshake->chaining_key, NOISE_HASH_LEN);
	handshake->state = HANDSHAKE_CREATED_RESPONSE;

	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
}

void handshake_consume_response(struct sg_message_handshake_response *src,
				struct sg_handshake *handshake,
				struct sg_static_identity *static_identity,
				struct sg_remote_identity *remote_identity)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 v[NOISE_VERSION_LEN];
	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];

	if (unlikely(!static_identity->has_identity))
		return;

	memcpy(hash, handshake->hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
	memcpy(ephemeral_private, handshake->ephemeral_private,
	       NOISE_PUBLIC_KEY_LEN);

	/* e */
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

	/* ee */
	if (!mix_dh(chaining_key, NULL, ephemeral_private, e))
		goto out;

	/* se */
	if (!mix_dh(chaining_key, NULL, static_identity->static_private, e))
		goto out;

	/* psk */
	mix_psk(chaining_key, hash, key, remote_identity->preshared_key);

	/* version */
	if (!message_decrypt(v, src->encrypted_version,
			     sizeof(src->encrypted_version), key, hash)) {
		goto out;
	}
	kdf(chaining_key, NULL, NULL, v, NOISE_HASH_LEN, 0, 0,
	    NOISE_VERSION_LEN, chaining_key);

	/* Success! Copy everything to handshake */

	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
	memcpy(&handshake->version, v, NOISE_VERSION_LEN);
	memcpy(handshake->hash, hash, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
	memcpy(handshake->send_rekey, chaining_key, NOISE_HASH_LEN);
	memcpy(handshake->recv_rekey, chaining_key, NOISE_HASH_LEN);
	handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	memzero_explicit(ephemeral_private, NOISE_PUBLIC_KEY_LEN);
}

bool handshake_create_rekey(struct sg_message_handshake_rekey *dst,
			    struct sg_handshake *handshake,
			    struct sg_noise_keypair *keypair,
			    struct sg_remote_identity *remote_identity)
{
	bool success = false;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 t[NOISE_TIMESTAMP_LEN];

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_REKEY);
	dst->header.len = cpu_to_le32(sg_message_len(*dst));
	memcpy(chaining_key, handshake->send_rekey, NOISE_HASH_LEN);
	rekey_reset(hash, remote_identity->remote_static);

	/* e */
	curve25519_generate_secret(e);
	if (!curve25519_generate_public(dst->unencrypted_ephemeral, e))
		goto out;
	message_ephemeral(dst->unencrypted_ephemeral,
			  dst->unencrypted_ephemeral, chaining_key, hash);

	/* es */
	if (!mix_dh(chaining_key, NULL, e, remote_identity->remote_static))
		goto out;

	/* ss */
	kdf(chaining_key, key, NULL, handshake->static_static, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);

	/* {t} */
	timestamp_now(t, handshake->epoch);
	message_encrypt(dst->encrypted_timestamp, t, NOISE_TIMESTAMP_LEN, key,
			hash);

	/* Success! */
	derive_key(&keypair->sending, chaining_key);
	memcpy(handshake->send_rekey, chaining_key, NOISE_HASH_LEN);
	success = true;
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	return success;
}

bool handshake_consume_rekey(struct sg_message_handshake_rekey *src,
			     struct sg_handshake *handshake,
			     struct sg_noise_keypair *keypair,
			     struct sg_static_identity *static_identity)
{
	bool replay_attack, success = false;
	u8 timestamp[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];

	memcpy(chaining_key, handshake->recv_rekey, NOISE_HASH_LEN);
	rekey_reset(hash, static_identity->static_public);

	/* e */
	message_ephemeral(e, src->unencrypted_ephemeral, chaining_key, hash);

	/* es */
	if (!mix_dh(chaining_key, NULL, static_identity->static_private, e))
		goto out;

	/* ss */
	kdf(chaining_key, key, NULL, handshake->static_static, NOISE_HASH_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, chaining_key);

	/* {t} */
	if (!message_decrypt(timestamp, src->encrypted_timestamp,
			     sizeof(src->encrypted_timestamp), key, hash))
		goto out;

	replay_attack = le64_to_cpup((void*)timestamp) -
		le64_to_cpup((void*)(handshake->remote_timestamp)) <= 0;
	if (replay_attack)
		goto out;

	/* Success! */
	derive_key(&keypair->receiving, chaining_key);
	memcpy(handshake->remote_timestamp, timestamp, NOISE_TIMESTAMP_LEN);
	memcpy(handshake->recv_rekey, chaining_key, NOISE_HASH_LEN);
	success = true;
out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	memzero_explicit(e, NOISE_HASH_LEN);
	return success;
}

void handshake_begin_session(struct sg_handshake *handshake,
			     struct sg_noise_keypair *keypair)
{
	if (handshake->state == HANDSHAKE_CONSUMED_RESPONSE) {
		derive_keys(&keypair->sending, &keypair->receiving,
			    handshake->chaining_key);
	} else {
		derive_keys(&keypair->receiving, &keypair->sending,
			    handshake->chaining_key);
	}
}

void message_data_encrypt(struct sg_message_data *msg,
			  struct sg_noise_keypair *keypair, u8 *data, int len)
{
	msg->header.type = MESSAGE_DATA;
	msg->header.len = cpu_to_le32(sg_noise_encrypted_len(len));

	 chacha20poly1305_encrypt(msg->encrypted_data, data, len, NULL, 0,
				  keypair->sending.counter,
				  keypair->sending.key);
}

bool message_data_decrypt(struct sg_message_data *msg,
			  struct sg_noise_keypair *keypair, u8 *data, int len)
{
	return chacha20poly1305_decrypt(data, msg->encrypted_data, len, NULL, 0,
					keypair->receiving.counter++,
					keypair->receiving.key);
}
