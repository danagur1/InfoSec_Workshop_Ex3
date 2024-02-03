#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "fw.h"

static struct nf_hook_ops forward_nh_ops;
static struct nf_hook_ops input_nh_ops;
static struct nf_hook_ops output_nh_ops;

unsigned int drop_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	printk(KERN_INFO "*** Packet Dropped ***\n");
	return NF_DROP;
}

unsigned int accept_hookfn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	printk(KERN_INFO "*** Packet Accepted ***\n");
	return NF_ACCEPT;
}

int register_hook(void){
	forward_nh_ops.hook = &drop_hookfn;
	forward_nh_ops.pf = PF_INET;
	forward_nh_ops.hooknum = NF_INET_FORWARD;
	forward_nh_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &forward_nh_ops);
}

void unregister_hook(void){
    nf_unregister_net_hook(&init_net, &forward_nh_ops);
}
