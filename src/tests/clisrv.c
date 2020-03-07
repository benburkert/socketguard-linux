#include "uapi/socketguard.h"

#include <assert.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>

void *client(void *arg);

static __u8 cli_private_key[SG_KEY_LEN];
static __u8 srv_private_key[SG_KEY_LEN];
static __u8 srv_public_key[SG_KEY_LEN];

int main()
{
	// open TCP socket

	int sockfd, connfd;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	assert(sockfd >= 0);

	// bind to a random port

	struct sockaddr_in srvaddr;
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_addr.s_addr = INADDR_ANY;
	srvaddr.sin_port = 0;

	assert(bind(sockfd, (struct sockaddr *) &srvaddr, sizeof(srvaddr)) == 0);

	int srvaddr_len = sizeof(srvaddr);

	assert(getsockname(sockfd, (struct sockaddr *) &srvaddr, &srvaddr_len) == 0);

	// start listening, register SocketGuard ULP

	assert(listen(sockfd, 1) == 0);

	assert(setsockopt(sockfd, SOL_TCP, TCP_ULP, "socketguard", sizeof("socketguard")) == 0);

	// set crypto info

	struct sg_crypto_info crypto_info;
	memset(&crypto_info, 0, sizeof(crypto_info));
	memcpy(crypto_info.static_private, srv_private_key, SG_KEY_LEN);

	assert(setsockopt(sockfd, SOL_SOCKETGUARD, SG_CRYPTO_INFO, &crypto_info, sizeof(crypto_info)) == 0);

	// read back the public key portion

	memset(&crypto_info, 0, sizeof(crypto_info));

	int crypto_len;
	assert(getsockopt(sockfd, SOL_SOCKETGUARD, SG_CRYPTO_INFO, &crypto_info, &crypto_len) == 0);

	assert(memcmp(crypto_info.static_public, srv_public_key, SG_KEY_LEN) == 0);

	__u8 empty[SG_KEY_LEN] = { 0 };
	assert(memcmp(crypto_info.static_private, empty, SG_KEY_LEN) == 0);

        // start client

	pthread_t tid;

	assert(pthread_create(&tid, NULL, client, &srvaddr) == 0);

	// accept client connection

	struct sockaddr cliaddr;
	int clilen;

	connfd = accept(sockfd, &cliaddr, &clilen);

	assert(pthread_join(tid, NULL) == 0);

	return 0;
}

void *client(void *arg)
{
	struct sockaddr_in *srvaddr = arg;

	// open TCP socket, register SocketGuard ULP

	int sockfd, connfd;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	assert(sockfd >= 0);

	assert(setsockopt(sockfd, SOL_TCP, TCP_ULP, "socketguard", sizeof("socketguard")) == 0);

	// setup initiator mode with client's private key

	struct sg_crypto_info crypto_info;
	memset(&crypto_info, 0, sizeof(crypto_info));
	memcpy(crypto_info.static_private, cli_private_key, SG_KEY_LEN);
	memcpy(crypto_info.peer_public, srv_public_key, SG_KEY_LEN);

	assert(setsockopt(sockfd, SOL_SOCKETGUARD, SG_CRYPTO_INFO, &crypto_info, sizeof(crypto_info)) == 0);

	// connect

	assert(connect(sockfd, (struct sockaddr *)srvaddr, sizeof(*srvaddr)) == 0);
}


static __u8 cli_private_key[SG_KEY_LEN] = {
	0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14,
	0x13, 0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
	0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
};
static __u8 srv_private_key[SG_KEY_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};
static __u8 srv_public_key[SG_KEY_LEN] = {
	0x8F, 0x40, 0xC5, 0xAD, 0xB6, 0x8F, 0x25, 0x62, 0x4A, 0xE5, 0xB2, 0x14,
	0xEA, 0x76, 0x7A, 0x6E, 0xC9, 0x4D, 0x82, 0x9D, 0x3D, 0x7B, 0x5E, 0x1A,
	0xD1, 0xBA, 0x6F, 0x3E, 0x21, 0x38, 0x28, 0x5F,
};
