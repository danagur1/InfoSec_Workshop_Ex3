#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

static struct nf_hook_ops by_table_nh_ops;
static rule_t *rule_table;
static int *rule_table_size;

int check_direction(struct sk_buff *skb, rule_t rule){
	return (((rule.direction==DIRECTION_IN)&&(skb->pkt_type==PACKET_OUTGOING)) || ((rule.direction==DIRECTION_OUT)&&(skb->pkt_type==PACKET_HOST))) || (rule.direction==3);
}

int check_ip(struct sk_buff *skb, rule_t rule){
	if ((ip_hdr(skb)->protocol!=IPPROTO_ICMP)&&(rule.protocol==PROT_ICMP)){
		return 0;
	}
	return ((ip_hdr(skb)->saddr & rule.src_prefix_mask) == (rule.src_ip & rule.src_prefix_mask)) && ((ip_hdr(skb)->daddr & rule.dst_prefix_mask) == (rule.dst_ip & rule.dst_prefix_mask));
}

int check_port(struct sk_buff *skb, rule_t rule){
    // packet is TCP
	if (rule.protocol==PROT_TCP){
		return (skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_TCP)&&
		(ntohs(tcp_hdr(skb)->source)==rule.src_port)&&(ntohs(tcp_hdr(skb)->dest)==rule.dst_port);
	}
	// packet is TCP
	if (rule.protocol==PROT_UDP){
		return (skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_UDP)&&
		(ntohs(udp_hdr(skb)->source)==rule.src_port)&&(ntohs(udp_hdr(skb)->dest)==rule.dst_port);
	}
    return 1;
}

int check_ack(struct sk_buff *skb, rule_t rule){
	if (rule.protocol==PROT_TCP) { 
		// check_port already checked that the packet is tcp
        return ((tcp_hdr(skb)->source)&&(rule.ack==ACK_YES))||((!tcp_hdr(skb)->source)&&(rule.ack==ACK_NO))||(ACK_ANY);
    }
	return 1;
}

unsigned int hookfn_by_rule_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	int rule_table_idx;
	printk(KERN_INFO "in hook function. rule_table_size=%d\n", *rule_table_size);
	for (rule_table_idx = 0; rule_table_idx<*rule_table_size; rule_table_idx++){
		printk(KERN_INFO "in loop for=%d\n", rule_table_idx);
		rule_t curr_rule= rule_table[rule_table_idx];
		printk(KERN_INFO "in hook function. check_direction=%d, check_ip=%d, check_port=%d, check_ack=%d\n", check_direction(skb, curr_rule), check_ip(skb, curr_rule), check_port(skb,curr_rule), check_ack(skb, curr_rule));
		if (check_direction(skb, curr_rule)&&check_ip(skb, curr_rule)&&check_port(skb,curr_rule)&&check_ack(skb, curr_rule)){
			if (curr_rule.action==NF_DROP){
				printk(KERN_INFO "Action taken is Drop\n");
			}
			if (curr_rule.action==NF_ACCEPT){
				printk(KERN_INFO "Action taken is Accept\n");
			}
			return curr_rule.action;
		}
	}
	printk(KERN_INFO "Action taken is Drop\n");
	return NF_DROP;
}

int register_hook(rule_t *input_rule_table, int *input_rule_table_size){
	printk(KERN_INFO "In register_hook\n");
	rule_table = input_rule_table;
	rule_table_size = input_rule_table_size;
	printk(KERN_INFO "In register_hook2\n");
	by_table_nh_ops.hook = &hookfn_by_rule_table;
	by_table_nh_ops.pf = PF_INET;
	printk(KERN_INFO "In register_hook3\n");
	by_table_nh_ops.hooknum = NF_INET_FORWARD;
	by_table_nh_ops.priority = NF_IP_PRI_FIRST;
	printk(KERN_INFO "In register_hook4\n");
	return nf_register_net_hook(&init_net, &by_table_nh_ops);
}

void unregister_hook(void){
    nf_unregister_net_hook(&init_net, &by_table_nh_ops);
}
