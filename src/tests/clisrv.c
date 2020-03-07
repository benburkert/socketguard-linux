#include "uapi/socketguard.h"

#include <assert.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>

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

	assert(setsockopt(sockfd, SOL_SOCKETGUARD, SOCKETGUARD_SET_INFO, NULL, 0) == 0);

	return 0;
}
