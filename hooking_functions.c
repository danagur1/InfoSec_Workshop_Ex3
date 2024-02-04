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

static struct nf_hook_ops forward_nh_ops;
static rule_t *rule_table;
int rule_table_size;

int check_direction(struct sk_buff *skb, rule_t rule){
	return (((rule.direction==DIRECTION_IN)&&(skb->pkt_type==PACKET_OUTGOING)) || ((rule.direction==DIRECTION_OUT)&&(skb->pkt_type==PACKET_HOST))) || (rule.direction==3);
}

int check_ip(struct sk_buff *skb, rule_t rule){
	return (skb->saddr & src_prefix_mask == curr_rule.src_ip & src_prefix_mask) && (skb->daddr & dst_prefix_mask == curr_rule.dst_ip & dst_prefix_mask)
}

int check_port(struct sk_buff *skb, rule_t rule){
	struct udphdr *udp_header;

    // packet is TCP
    if ((skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_TCP)&&(rule->protocol==PROT_TCP)) {
        return (ntohs(tcp_hdr(skb)->source)==rule->src_port)&&(ntohs(tcp_hdr(skb)->dest)==rule->dst_port);
    }
	// packet is UDP
    if ((skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_UDP)&&(rule->protocol==PROT_UDP)) {
        return (ntohs(udp_hdr(skb)->source)==rule->src_port)&&(ntohs(udp_hdr(skb)->dest)==rule->dst_port);
    }
	// packet is ICMP
    if ((skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_ICMP)&&(rule->protocol==PROT_ICMP)) {
        return (ntohs(icmp_hdr(skb)->source)==rule->src_port)&&(ntohs(icmp_hdr(skb)->dest)==rule->dst_port);
    }
}

int check_ack(struct sk_buff *skb, rule_t rule){
	if ((skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_TCP)) {
        return ((tcp_hdr(skb)->source)&&(rule->ack==ACK_YES))||((!tcp_hdr(skb)->source)&&(rule->ack==ACK_NO))||(ACK_ANY);
    }
}

unsigned int hookfn_by_rule_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	while (int rule_table_idx = 0; rule_table_idx<rule_table_size; rule_table_idx++){
		rule_t curr_rule= rule_table[rule_table_idx];
		if (check_direction(skb, curr_rule)&&check_ip(skb, curr_rule)&&check_port(skb,curr_rule)&&check_ack(skb, cur)){
			if (curr_rule->action==NF_DROP){
				printk(KERN_INFO "Action taken is Drop\n");
			}
			if (curr_rule->action==NF_ACCEPT){
				printk(KERN_INFO "Action taken is Accept\n");
			}
			return curr_rule->action;
		}
	}
	printk(KERN_INFO "Action taken is Drop\n");
	return NF_DROP;
}

int register_hook(rule_t *input_rule_table, int input_rule_table_size){
	rule_table = input_rule_table;
	rule_table_size = input_rule_table_size;
	forward_nh_ops.hook = &hookfn_by_rule_table;
	forward_nh_ops.pf = PF_INET;
	forward_nh_ops.hooknum = NF_INET_FORWARD;
	forward_nh_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &forward_nh_ops);
}

void unregister_hook(void){
    nf_unregister_net_hook(&init_net, &forward_nh_ops);
}
