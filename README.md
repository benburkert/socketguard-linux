Kernel Socketguard {#kernel_socketguard}
==================

Overview
--------

Socketguard is an Upper Layer Protocol (ULP) that provides
authentication and confidentiality.

User interface
--------------

For both client & server TCP connections, enable Socketguard on the
socket with sectsockopt(2).

Example: Initiating Encryption On a Client Connection
-----------------------------------------------------

``` {.c}
int fd = socket(AF_INIT, SOCK_STREAM, 0);
struct sg_crypto_info crypto_info = {
  .static_private = priv,
  .peer_public = srv_pub,
};

setsockopt(fd, SOL_TCP, TCP_ULP, "socketguard", sizeof("socketguard"));
setsockopt(fd, SOL_SOCKETGUARD, SG_CRYPTO_INFO, &crypto_info, sizeof(crypto_info));

connect(fd, &srv_addr, sizeof(srv_addr));
```

Example: Server Side Encryption
-------------------------------

``` {.c}
int sockfd = socket(AF_INIT, SOCK_STREAM, 0);
struct sg_crypto_info crypto_info = {
  .static_private = priv,
};

bind(sockfd, &srv_addr, sizeof(srv_addr));
setsockopt(sockfd, SOL_TCP, TCP_ULP, "socketguard", sizeof("socketguard"));
setsockopt(sockfd, SOL_SOCKETGUARD, SG_CRYPTO_INFO, &crypto_info, siezof(crypto_info));

connfd = accept(sockfd, &cli_addr, &cli_len);
```

Install
-------

The socketguard kernel module requires Linux Kernel version 5.6 or
greater. First load the crypto modules socketguard depends on:

``` {.sh}
$ modprobe curve25519 libblake2s libchacha20poly1305 libchacha
```

Then build and load the socketguard module:

``` {.sh}
$ cd src
$ make
$ sudo insmod ./socketguard.ko
```

Protocol
--------

### Initiator Handshake

The initiator sends the message:

``` {.}
msg = handshake_initiation {
  u8 message_type
  u8 reserved_zero[3]
  u8 message_length[4]
  u8 unencrypted_ephemeral[32]
  u8 encrypted_version[24]
  u8 encrypted_static[48]
}
```

The fields are populated as follows:

``` {.}
initiator.chaining_key = HASH(CONSTRUCTION)
initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
initiator.ephemeral_private = DH_GENERATE()
initiator.version = VERSION()
msg.message_type = 1
msg.reserved_zero = { 0, 0, 0 }
msg.message_length = LE_U32(104)

msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)

temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
initiator.chaining_key = HMAC(temp, 0x1)

temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
initiator.chaining_key = HMAC(temp, 0x1)
key = HMAC(temp, initiator.chaining_key || 0x2)

msg.encrypted_version = AEAD_SEAL(key, 0, initiator.version, initiator.hash)
initiator.hash = HASH(initiator.hash || msg.encrypted_version)

temp = HMAC(initiator.chaining_key, initiator.version)
initiator.chaining_key = HMAC(temp, 0x1)
key = HMAC(temp, initiator.chaining_key || 0x2)

msg.encrypted_static = AEAD_SEAL(key, 0, initiator.static_public, initiator.hash)
initiator.hash = HASH(initiator.hash || msg.encrypted_static)

temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
initiator.chaining_key = HMAC(temp, 0x1)
key = HMAC(temp, initiator.chaining_key || 0x2)
```

The responder consumes the message fields as follows:

``` {.}
responder.chaining_key = HASH(CONSTRUCTION)
responder.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)

responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)

temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
responder.chaining_key = HMAC(temp, 0x1)

temp = HMAC(responder.chaining_key, DH(responder.static_public, msg.unencrypted_ephemeral))
responder.chaining_key = HMAC(temp, 0x1)
key = HMAC(temp, responder.chaining_key || 0x2)

initiator.version = AEAD_OPEN(key, 0, msg.encrypted_version, responder.hash);
responder.hash = HASH(responder.hash || msg.encrypted_version)

temp = HMAC(responder.chaining_key, initiator.version)
responder.chaining_key = HMAC(temp, 0x1)
key = HMAC(temp, responder.chaining_key || 0x2)

initiator.static = AEAD_OPEN(key, 0, msg.encrypted_static, responder.hash);
responder.hash = HASH(responder.hash || msg.encrypted_static)

temp = HMAC(responder.chaining_key, DH(responder.static_private, initiator.static))
responder.chaining_key = HMAC(temp, 0x1)
key = HMAC(temp, responder.chaining_key || 0x2)
```

### Responder Handshake

The responder sends back the message:

``` {.}
msg = handshake_response {
  u8 message_type
  u8 reserved_zero[3]
  u8 message_length[4]
  u8 unencrypted_ephemeral[32]
  u8 encrypted_version[24]
}
```

The fields are populated as follows:

``` {.}
responder.ephemeral_private = DH_GENERATE()
responder.version = VERSION_NEGOTIATE(initiator.version)
msg.message_type = 2
msg.reserved_zero = { 0, 0, 0 }
msg.message_length = LE_U32(56)

msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)

temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
responder.chaining_key = HMAC(temp, 0x1)

temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
responder.chaining_key = HMAC(temp, 0x1)

temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
responder.chaining_key = HMAC(temp, 0x1)

temp = HMAC(responder.chaining_key, preshared_key)
responder.chaining_key = HMAC(temp, 0x1)
temp2 = HMAC(temp, responder.chaining_key || 0x2)
key = HMAC(temp, temp2 || 0x2)
responder.hash = HASH(responder.hash || temp2)

msg.encrypted_version = AEAD_SEAL(key, 0, responder.version, responder.hash)
responder.hash = HASH(responder.hash || msg.encrypted_version)

temp = HMAC(responder.chaining_key, responder.version)
responder.chaining_key = HMAC(temp, 0x1)
```

The initiator consumes the message fields as follows:

``` {.}
initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)

temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
initiator.chaining_key = HMAC(temp, 0x1)

temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, msg.unencrypted_ephemeral))
initiator.chaining_key = HMAC(temp, 0x1)

temp = HMAC(initiator.chaining_key, DH(initiator.static_private, msg.unencrypted_ephemeral))
initiator.chaining_key = HMAC(temp, 0x1)

temp = HMAC(initiator.chaining_key, preshared_key)
initiator.chaining_key = HMAC(temp, 0x1)
temp2 = HMAC(temp, initiator.chaining_key || 0x2)
key = HMAC(temp, temp2 || 0x2)
initiator.hash = HASH(initator.hash || temp2)

responder.version = AEAD_OPEN(key, 0, msg.encrypted_version, initiator.hash)
initator.hash = HASH(initator.hash || msg.encrypted_version)

temp = HMAC(initiator.chaining_key, responder.version)
initiator.chaining_key = HMAC(temp, 0x1)
```

### Handshake Rekey

The sender initiates a rekey by sending the following message:

``` {.}
msg = handshake_rekey {
  u8 message_type
  u8 reserved_zero[3]
  u8 message_length[4]
  u8 unencrypted_ephemeral[32]
  u8 encrypted_timestamp[24]
}
```

The fields are populated as follows:

``` {.}
sender.ephemeral_private = DH_GENERATE()
msg.message_type = 3
msg.reserved_zero = { 0, 0, 0 }
msg.message_length = LE_U32(56)

sender.hash = HASH(HASH(HASH(CONSTRUCTION) || IDENTIFIER) || receiver.static_public)

msg.unencrypted_ephemeral = DH_PUBKEY(sender.ephemeral_private)
sender.hash = HASH(sender.hash || msg.unencrypted_ephemeral)

temp = HMAC(sender.send_rekey, DH(sender.ephemeral_private, receiver.static_public))
sender.send_rekey = HMAC(temp, 0x1)

temp = HMAC(sender.send_rekey , DH(sender.static_private, receiver.static_public))
sender.send_rekey = HMAC(temp, 0x1)
key = HMAC(temp, sender.send_key || 0x2)

msg.encrypted_timestamp = AEAD_SEAL(key, 0, NOW(), sender.hash)
```

The receiver consumes the message fields as follows:

``` {.}
receiver.hash = HASH(HASH(HASH(CONSTRUCTION) || IDENTIFIER) || sender.static_public)

receiver.hash = HASH(receiver.hash || msg.unencrypted_ephemeral)

temp = HMAC(receiver.recv_rekey, DH(receiver.static_private, msg.ephemeral_public))
receid.recv_rekey = HMAC(temp, 0x1)

temp = HMAC(receiver.recv_rekey, DH(receiver.static_private, sender.static_public))
receiver.recv_rekey = HMAC(temp, 0x1)
key = HMAC(temp, receiver.recv_key || 0x2)

timestamp = AEAD_OPEN(key, 0, msg.encrypted_timestamp, receiver.hash)
```

### Data Message

``` {.}
msg = message_data {
  u8 message_type
  u8 reserved_zero[3]
  u8 message_length[4]
  u8 encrypted_data[]
}
```

``` {.}
msg.message_type = 4
msg.reserved_zero = { 0, 0, 0 }
msg.message_length = LE_U32(encrypted_data_length)

// TODO: pad out data to multiple of 16
msg.encrypted_data = AEAD(sender.sending_key, sender.sending_key_counter, data, [empty])
```
