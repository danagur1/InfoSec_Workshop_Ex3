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

int check_direction(struct sk_buff *skb, rule_t rule){
	struct net_device *dev = skb->dev;
	if (dev) {
		printk(KERN_INFO "in check_direction: dev->name=%s\n", dev->name);
        if (rule.direction==DIRECTION_IN) {
            return strcmp(dev->name, "enp0s9") == 0;
        } else if (rule.direction==DIRECTION_OUT) {
            return strcmp(dev->name, "enp0s8") == 0;
        } else {
			printk(KERN_INFO "in check_direction: no dev\n");
            return -1;
    	}
	}
	return 0;
}

int check_ip(struct sk_buff *skb, rule_t rule){
	if ((ip_hdr(skb)->protocol!=IPPROTO_ICMP)&&(rule.protocol==PROT_ICMP)){
printk(KERN_INFO "check_ip return 0 because of icmp");
		return 0;
	}
printk(KERN_INFO "1:%u, 2:%u, 3:%u", ip_hdr(skb)->saddr, rule.src_prefix_mask, rule.src_ip);
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

static int compare_logs(log_row_t *log1, log_row_t *log2){
    return (log1->timestamp==log2->timestamp)&&(log1->protocol==log2->protocol)&&(log1->action==log2->action)&&
    (log1->src_ip==log2->src_ip)&&(log1->dst_ip==log2->dst_ip)&&(log1->src_port==log2->src_port)&&
    (log1->dst_port==log2->dst_port)&&(log1->reason==log2->reason);
}


long get_time(void){
	struct timespec64 current_time;
    ktime_get_real_ts64(&current_time);
    return (unsigned long)current_time.tv_sec;
}

void exist_log_check(log_row_t *log){
	log_row_t *log_exist;
	log_exist = find_identical_log(log, compare_logs);
	if (log_exist==NULL){
		printk(KERN_INFO "Before add_to_log_list\n");
		add_to_log_list(log);
	}
	else{
		printk(KERN_INFO "Before updating log\n");
		log_exist->count = log_exist->count+1;
		log_exist->timestamp = log->timestamp;
	}
}

reason_t find_special_reason(int reason_code){
	if (reason_code==1){
		return REASON_ILLEGAL_VALUE;
	}
	else if (reason_code==2){
		return REASON_NO_MATCHING_RULE;
	}
	else if (reason_code==3){
		return REASON_FW_INACTIVE;
	}
}

log_row_t log_by_protocol(__u8 protocol, struct sk_buff *skb, reason_t reason, unsigned char action){
	if ((protocol==IPPROTO_TCP)&&(skb->protocol == htons(ETH_P_IP))){
		return (log_row_t){get_time(), PROT_TCP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, tcp_hdr(skb)->source,
		tcp_hdr(skb)->dest, reason, 0};
	}
	if ((protocol==IPPROTO_UDP)&&(skb->protocol == htons(ETH_P_IP))){
		return (log_row_t){get_time(), PROT_UDP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, udp_hdr(skb)->source,
		udp_hdr(skb)->dest, reason, 0};
	}
	if (protocol==IPPROTO_ICMP){
		return (log_row_t){get_time(), PROT_ICMP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, udp_hdr(skb)->source,
		udp_hdr(skb)->dest, reason, 0};
	}
	return NULL;
}

void log(rule_t *rule, struct sk_buff *skb, int rule_table_idx, int special_reason){
	log_row_t log;
	reason_t reason = rule_table_idx;
	unsigned char action;
	if (strcmp(dev->name, "lo")){
		//no log in case of loopback
		return;
	}
	//handle special cases wnen no rule matching the action:
	if (special_reason>0){
		reason = find_special_reason(special_reason)
		action = NF_DROP;
	}
	else {
		action = rule->action;
		printk(KERN_INFO "Just put action- 3");
	}
	log = log_by_protocol(ip_hdr(skb)->protocol, skb, reason, action)
	if (log==NULL){
		return;
	}
	printk(KERN_INFO "Before exist_log_check\n");
	exist_log_check(&log);
}

unsigned int hookfn_by_rule_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	int rule_table_idx;
	int check_direction_result;
	printk(KERN_INFO "in hook function. rule_table_size=%d\n", *rule_table_size);
	for (rule_table_idx = 0; rule_table_idx<*rule_table_size; rule_table_idx++){
		rule_t curr_rule= rule_table[rule_table_idx];
		printk(KERN_INFO "in loop for=%d\n", rule_table_idx);
		printk(KERN_INFO "in hook function. check_direction=%d, check_ip=%d, check_port=%d, check_ack=%d\n", check_direction(skb, curr_rule), check_ip(skb, curr_rule), check_port(skb,curr_rule), check_ack(skb, curr_rule));
		check_direction_result = check_direction(skb, curr_rule);
		if (check_direction_result==-1){
			log(NULL, skb, 0, 1);
			return NF_DROP;
		}
		if (check_direction_result&&check_ip(skb, curr_rule)&&check_port(skb,curr_rule)&&check_ack(skb, curr_rule)){
			if (curr_rule.action==NF_DROP){
				printk(KERN_INFO "Action taken is Drop\n");
			}
			if (curr_rule.action==NF_ACCEPT){
				printk(KERN_INFO "Action taken is Accept\n");
			}
			log(&curr_rule, skb, rule_table_idx, 0);
			return curr_rule.action;
		}
	}
	printk(KERN_INFO "No rule found. rule_table_size=%d\n", *rule_table_size);
	if (*rule_table_size==0){
		printk(KERN_INFO "No rules in table\n");
		log(NULL, skb, 0, 3);
	}
	else{
		printk(KERN_INFO "No rule matched\n");
		log(NULL, skb, 0, 2);
	}
	printk(KERN_INFO "Action taken is Drop\n");
	return NF_DROP;
}

int register_hook(rule_t *input_rule_table, int *input_rule_table_size){
	printk(KERN_INFO "In register_hook\n");
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
