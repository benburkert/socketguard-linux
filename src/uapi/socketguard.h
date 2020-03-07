#ifndef _UAPI_SOCKETGUARD_H
#define _UAPI_SOCKETGUARD_H

#include <linux/types.h>

#define	SOL_SOCKETGUARD	0x2C4+1

// socket options
#define SG_CRYPTO_INFO	1

#define SG_KEY_LEN	32

struct sg_crypto_info {
	__u16 version;

	__u8  static_public[SG_KEY_LEN];
	__u8  static_private[SG_KEY_LEN];
	__u8  peer_public[SG_KEY_LEN];
	__u8  preshared_key[SG_KEY_LEN];
};

#endif /* _UAPI_SOCKETGUARD_H */

