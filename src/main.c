#include "context.h"
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

static struct tcp_ulp_ops sg_tcp_ulp_ops __read_mostly = {
	.name	 = "socketguard",
	.owner	 = THIS_MODULE,
	.init	 = ulp_init,
	.clone   = ulp_clone,
	.release = ulp_release,
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
