#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include "fw.h"
#include "manage_log_list.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

static struct nf_hook_ops by_table_nh_ops;
static rule_t *rule_table;
static int *rule_table_size;

/*
Checking functions- compare information from the packet and rules. 
return 1 in case of match, 0 in case of no match, -1 in case of illegal value
*/

int check_xmas_tree_packet(struct sk_buff *skb){
    struct tcphdr *tcp_header;
    if (ip_hdr(skb)->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (tcp_header->syn && tcp_header->fin && tcp_header->urg &&
            tcp_header->psh && tcp_header->rst && tcp_header->ack) {
            return 1;
        }
    }
	return 0;
}

int check_direction(struct sk_buff *skb, rule_t rule){
	struct net_device *dev = skb->dev;
	if (dev) {
        if (rule.direction==DIRECTION_IN) {
            return strcmp(dev->name, "enp0s9") == 0;
        } else if (rule.direction==DIRECTION_OUT) {
            return strcmp(dev->name, "enp0s8") == 0;
        } else if (rule.direction==DIRECTION_ANY){
            return (strcmp(dev->name, "enp0s8") == 0) || (strcmp(dev->name, "enp0s9") == 0);
    	}
		else{
			return -1;
		}
	}
	return 0;
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

/*
Logging functions
*/

static int compare_logs(log_row_t *log1, log_row_t *log2){
	//compare log rows by all parameters except count
	return (log1->protocol==log2->protocol)&&(log1->action==log2->action)&&
    (log1->src_ip==log2->src_ip)&&(log1->dst_ip==log2->dst_ip)&&(log1->src_port==log2->src_port)&&
    (log1->dst_port==log2->dst_port)&&(log1->reason==log2->reason);
}


long get_time(void){
	//returns the current time in seconds
	unsigned long result;
	struct timespec64 ts;
    ktime_get_real_ts64(&ts);
	result = ts.tv_sec;
    return result;
}

void exist_log_check(log_row_t *log){
	log_row_t *log_exist;
	log_exist = find_identical_log(log, compare_logs);
	if (log_exist==NULL){
		add_to_log_list(log);
	}
	else{
		if (log_exist==NULL){
			return;
		}
		log_exist->count = log_exist->count+1;
		log_exist->timestamp = log->timestamp;
	}
}

reason_t find_special_reason(int reason_code){
	if (reason_code==3){
		return REASON_FW_INACTIVE;
	}
	else if (reason_code==2){
		return REASON_NO_MATCHING_RULE;
	}
	else if (reason_code==4){
		return REASON_XMAS_PACKET;
	}
	else {
		return REASON_ILLEGAL_VALUE;
	}
}

log_row_t log_by_protocol(__u8 protocol, struct sk_buff *skb, reason_t reason, unsigned char action, int *no_log){
	log_row_t log;
	if ((protocol==IPPROTO_TCP)&&(skb->protocol == htons(ETH_P_IP))){
		log = (log_row_t){get_time(), PROT_TCP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, tcp_hdr(skb)->source,
		tcp_hdr(skb)->dest, reason, 0};
	}
	else if ((protocol==IPPROTO_UDP)&&(skb->protocol == htons(ETH_P_IP))){
		log = (log_row_t){get_time(), PROT_UDP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, udp_hdr(skb)->source,
		udp_hdr(skb)->dest, reason, 0};
	}
	else if (protocol==IPPROTO_ICMP){
		log = (log_row_t){get_time(), PROT_ICMP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, 0,
		0, reason, 0};
	}
	else{
		*no_log = 1;
	}
	return log;
}

void log(rule_t *rule, struct sk_buff *skb, int rule_table_idx, int special_reason){
	log_row_t *log = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_KERNEL);
	reason_t reason = rule_table_idx;
	unsigned char action;
	struct net_device *dev = skb->dev;
	int no_log = 0;
	if (strcmp(dev->name, "lo")==0){
		//no log in case of loopback
		return;
	}
	//handle special cases wnen no rule matching the action:
	if (special_reason>0){
		reason = find_special_reason(special_reason);
		action = NF_DROP;
	}
	else {
		action = rule->action;
	}
	*log = log_by_protocol(ip_hdr(skb)->protocol, skb, reason, action, &no_log);
	if (no_log){
		return;
	}
	exist_log_check(log);
}

/*
The hook function of the firewall:
*/
unsigned int hookfn_by_rule_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	int rule_table_idx;
	int check_direction_result;
	if (skb==NULL){
	}
	if (check_xmas_tree_packet(skb)){
		log(NULL, skb, 0, 4);
		return NF_DROP;
	}
	for (rule_table_idx = 0; rule_table_idx<*rule_table_size; rule_table_idx++){
		rule_t curr_rule= rule_table[rule_table_idx];
		check_direction_result = check_direction(skb, curr_rule);
		if (check_direction_result==-1){
			log(NULL, skb, 0, 1);
			return NF_DROP;
		}
		if (check_direction_result&&check_ip(skb, curr_rule)&&check_port(skb,curr_rule)&&check_ack(skb, curr_rule)){
			log(&curr_rule, skb, rule_table_idx, 0);
			return curr_rule.action;
		}
	}
	if (*rule_table_size==0){
		log(NULL, skb, 0, 3);
	}
	else{
		log(NULL, skb, 0, 2);
	}
	return NF_DROP;
}

int register_hook(rule_t *input_rule_table, int *input_rule_table_size){
	init_log_list();
	rule_table = input_rule_table;
	rule_table_size = input_rule_table_size;
	by_table_nh_ops.hook = &hookfn_by_rule_table;
	by_table_nh_ops.pf = PF_INET;
	by_table_nh_ops.hooknum = NF_INET_FORWARD;
	by_table_nh_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &by_table_nh_ops);
}

void unregister_hook(void){
    nf_unregister_net_hook(&init_net, &by_table_nh_ops);
}
