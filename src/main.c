#include "proto.h"

#include <linux/init.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/tcp.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ben Burkert");
MODULE_DESCRIPTION("TODO");
MODULE_VERSION("0.1");
MODULE_ALIAS_TCP_ULP("socketguard");

// lock_sock(sk) is held
static int ulp_init(struct sock *sk)
{
	init_protos(sk);

	return 0;
}

static struct tcp_ulp_ops sg_tcp_ulp_ops __read_mostly = {
	.name			= "socketguard",
	.owner			= THIS_MODULE,
	.init			= ulp_init,
};

static int __init mod_init(void)
{
	tcp_register_ulp(&sg_tcp_ulp_ops);
	return 0;
}

static void __exit mod_exit(void)
{
	tcp_unregister_ulp(&sg_tcp_ulp_ops);
}

module_init(mod_init);
module_exit(mod_exit);
