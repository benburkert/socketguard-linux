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

// lock_sock(sk) held
static int ulp_init(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct proto *sg_prot;
	struct sg_context *ctx;

	init_protos(sk);
	sg_prot = get_sg_proto(sk);

	ctx = ctx_create(sk);
	if (!ctx)
		return -ENOMEM;


	write_lock_bh(&sk->sk_callback_lock);
	rcu_assign_pointer(icsk->icsk_ulp_data, ctx);
	sk->sk_prot = sg_prot;
	write_unlock_bh(&sk->sk_callback_lock);

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
