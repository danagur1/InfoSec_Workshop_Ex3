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

int check_direction(struct sk_buff *skb, rule_t rule){
	struct net_device *dev = skb->dev;
	if (dev) {
		printk(KERN_INFO "in check_direction: dev->name=%s and direction=%hhu\n", dev->name, rule.direction);
        if (rule.direction==DIRECTION_IN) {
            return strcmp(dev->name, "enp0s9") == 0;
        } else if (rule.direction==DIRECTION_OUT) {
            return strcmp(dev->name, "enp0s8") == 0;
        } else if (rule.direction==DIRECTION_ANY){
            return (strcmp(dev->name, "enp0s8") == 0) || (strcmp(dev->name, "enp0s9") == 0);
    	}
		else{
printk(KERN_INFO "failed to match direction\n");
			return -1;
		}
	}
	return 0;
}

int check_ip(struct sk_buff *skb, rule_t rule){
	if ((ip_hdr(skb)->protocol!=IPPROTO_ICMP)&&(rule.protocol==PROT_ICMP)){
		//printk(KERN_INFO "check_ip return 0 because of icmp");
		return 0;
	}
	//printk(KERN_INFO "1:%u, 2:%u, 3:%u", ip_hdr(skb)->saddr, rule.src_prefix_mask, rule.src_ip);
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
	printk(KERN_INFO "Compering, log1->protocol=%d, log2->protocol=%d, result=%d", log1->protocol, log2->protocol, (log1->protocol==log2->protocol));
	printk(KERN_INFO "Compering, log1->action=%d, log2->action=%d, result=%d", log1->action, log2->action, (log1->action==log2->action));
	printk(KERN_INFO "Compering, log1->src_ip=%d, log2->src_ip=%d, result=%d", log1->src_ip, log2->src_ip, (log1->src_ip==log2->src_ip));
	printk(KERN_INFO "Compering, log1->dst_ip=%d, log2->dst_ip=%d, result=%d", log1->dst_ip, log2->dst_ip, (log1->dst_ip==log2->dst_ip));
	printk(KERN_INFO "Compering, log1->src_port=%d, log2->src_port=%d, result=%d", log1->src_port, log2->src_port,(log1->src_port==log2->src_port));
	printk(KERN_INFO "Compering, log1->dst_port=%d, log2->dst_port=%d, result=%d", log1->dst_port, log2->dst_port, (log1->dst_port==log2->dst_port));
	printk(KERN_INFO "Compering, log1->reason=%d, log2->reason=%d, result=%d", log1->reason, log2->reason, (log1->reason==log2->reason));
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
printk(KERN_INFO "In time got %lu\n", result);
    return result;
}

void exist_log_check(log_row_t *log){
	log_row_t *log_exist;
	log_exist = find_identical_log(log, compare_logs);
	if (log_exist==NULL){
		printk(KERN_INFO "Before add_to_log_list\n");
		add_to_log_list(log);
get_log_list_length();
	}
	else{
		printk(KERN_INFO "Before updating log\n");
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
printk(KERN_INFO "At the end of log_by_protocol function. time passed=%lu\n", log.timestamp);
	return log;
}

void log(rule_t *rule, struct sk_buff *skb, int rule_table_idx, int special_reason){
	log_row_t *log = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_KERNEL);
	reason_t reason = rule_table_idx;
	unsigned char action;
	struct net_device *dev = skb->dev;
	int no_log = 0;
	printk(KERN_INFO "Starting log\n");
	if (strcmp(dev->name, "lo")==0){
		//no log in case of loopback
		printk(KERN_INFO "exist log cause of loopback. dev->name=%s\n", dev->name);
		return;
	}
	//handle special cases wnen no rule matching the action:
	if (special_reason>0){
		reason = find_special_reason(special_reason);
		action = NF_DROP;
	}
	else {
		action = rule->action;
		//printk(KERN_INFO "Just put action- 3");
	}
	*log = log_by_protocol(ip_hdr(skb)->protocol, skb, reason, action, &no_log);
	if (no_log){
		printk(KERN_INFO "exist log cause of error in ptotocol\n");
		return;
	}
	printk(KERN_INFO "exit log normally\n");
	exist_log_check(log);
printk(KERN_INFO "At the very end of log function. time passed is checked now");
get_log_list_length();
}

/*
The hook function of the firewall:
*/

unsigned int hookfn_by_rule_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	int rule_table_idx;
	int check_direction_result;
printk(KERN_INFO "rule_table in 0 .direction=%hhu\n", rule_table[0].direction);
if (skb==NULL){
printk(KERN_INFO "NULL error in log hookfn_by_rule_table\n");
}
	printk(KERN_INFO "in hook function. rule_table_size=%d\n", *rule_table_size);
	for (rule_table_idx = 0; rule_table_idx<*rule_table_size; rule_table_idx++){
		rule_t curr_rule= rule_table[rule_table_idx];
		printk(KERN_INFO "in loop for=%d\n", rule_table_idx);
		printk(KERN_INFO "in hook function. check_direction=%d, check_ip=%d, check_port=%d, check_ack=%d\n", check_direction(skb, curr_rule), check_ip(skb, curr_rule), check_port(skb,curr_rule), check_ack(skb, curr_rule));
printk(KERN_INFO "for current rule direction=%hhu\n", curr_rule.direction);
		check_direction_result = check_direction(skb, curr_rule);
		if (check_direction_result==-1){
printk(KERN_INFO "before log function call");
			log(NULL, skb, 0, 1);
printk(KERN_INFO "At the very end of hook function. time passed is checked now");
get_log_list_length();
			return NF_DROP;
		}
		if (check_direction_result&&check_ip(skb, curr_rule)&&check_port(skb,curr_rule)&&check_ack(skb, curr_rule)){
			if (curr_rule.action==NF_DROP){
				printk(KERN_INFO "Action taken is Drop!!!\n");
			}
			if (curr_rule.action==NF_ACCEPT){
				printk(KERN_INFO "Action taken is Accept\n");
			}
			log(&curr_rule, skb, rule_table_idx, 0);
printk(KERN_INFO "At the very end of hook function. time passed is checked now");
get_log_list_length();
			return curr_rule.action;
		}
	}
	//printk(KERN_INFO "No rule found. rule_table_size=%d\n", *rule_table_size);
	if (*rule_table_size==0){
		log(NULL, skb, 0, 3);
printk(KERN_INFO "At the very end of hook function. time passed is checked now");
get_log_list_length();

	}
	else{
		
		log(NULL, skb, 0, 2);
printk(KERN_INFO "At the very end of hook function. time passed is checked now");
get_log_list_length();
	}
		printk(KERN_INFO "here\n");
get_log_list_length();
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
