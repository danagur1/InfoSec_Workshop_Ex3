#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include "fw.h"
#include "manage_log_list.h"
#include "manage_conn_list.h"

#define TCP_STATES_TABLE_ROWS 17
#define TCP_STATES_TABLE_COLS 16
#define TCP_RULES_AMOUNT 20
#define TIMEOUT 2
#define CLIENT_PACK_ONLY_STATES 5
#define SERVER_PACKS_ONLY_STATES 3
#define BOTH_PACK_STATES 6

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

static struct nf_hook_ops by_table_nh_ops;
static rule_t *rule_table;
static int *rule_table_size;

//constatnt defenitions for the TCP state machine table:
state_t tcp_states_table[TCP_STATES_TABLE_ROWS][TCP_STATES_TABLE_COLS];
int rules_priv_state[TCP_RULES_AMOUNT] = {STATE_CLOSED, STATE_CLOSED, STATE_CLOSED_TO_SYN_RECEIVED, STATE_SYN_SENT, STATE_SYN_SENT_TO_SYN_RECEIVED, STATE_SYN_SENT, 
	STATE_SYN_SENT_TO_ESTABLISHED, STATE_SYN_RECEIVED, STATE_ESTABLISHED, STATE_ESTABLISHED_TO_CLOSE_WAIT, STATE_CLOSE_WAIT, STATE_LAST_ACK, STATE_ESTABLISHED, STATE_FIN_WAIT_1, 
	STATE_FIN_WAIT_1_TO_CLOSING, STATE_FIN_WAIT_1, STATE_CLOSING, STATE_FIN_WAIT_2, STATE_FIN_WAIT_2_TO_TIME_WAIT, STATE_FIN_WAIT_2_TO_TIME_WAIT};
int rules_packs_flags[TCP_RULES_AMOUNT] = {0b1001, 0b1000, 0b1101, 01000, 0b0101, 0b1100, 0b0101, 0b0100, 0b0010, 0b0101, 0b0011, 0b0100, 0b0011, 0b0010, 0b0101, 0b0100, 0b0100, 
	0b0010, 0b0010, 0b0101};
int rules_next_state_rule[TCP_RULES_AMOUNT] = {STATE_SYN_SENT, STATE_CLOSED_TO_SYN_RECEIVED, STATE_SYN_RECEIVED, STATE_SYN_SENT_TO_SYN_RECEIVED, STATE_SYN_RECEIVED, 
	STATE_SYN_SENT_TO_ESTABLISHED, STATE_ESTABLISHED, STATE_ESTABLISHED, STATE_ESTABLISHED_TO_CLOSE_WAIT, STATE_CLOSE_WAIT, STATE_LAST_ACK, STATE_CLOSED, STATE_FIN_WAIT_1, 
	STATE_FIN_WAIT_1_TO_CLOSING, STATE_CLOSING, STATE_FIN_WAIT_2, STATE_TIME_WAIT, STATE_FIN_WAIT_2, STATE_FIN_WAIT_2_TO_TIME_WAIT, STATE_TIME_WAIT};
int client_packs_only_states[CLIENT_PACK_ONLY_STATES] = {STATE_SYN_SENT, STATE_SYN_SENT_TO_ESTABLISHED, STATE_SYN_SENT_TO_SYN_RECEIVED, STATE_ESTABLISHED, 
	STATE_ESTABLISHED_TO_CLOSE_WAIT};
int server_packs_only_states[SERVER_PACKS_ONLY_STATES] = {STATE_CLOSED, STATE_CLOSED_TO_SYN_RECEIVED, STATE_SYN_RECEIVED};
int both_packs_only_states[BOTH_PACK_STATES] = {STATE_ESTABLISHED, STATE_FIN_WAIT_1, STATE_FIN_WAIT_2, STATE_CLOSE_WAIT, STATE_CLOSING, STATE_LAST_ACK};
int neither_packet_state = STATE_TIME_WAIT;

int is_tcp_packet(struct sk_buff *skb){
	return (skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_TCP);
}

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

int check_protocol_and_port(struct sk_buff *skb, rule_t rule){
    // packet is TCP
	if (rule.protocol==PROT_TCP){
		return is_tcp_packet(skb)&&(ntohs(tcp_hdr(skb)->source)==rule.src_port)&&(ntohs(tcp_hdr(skb)->dest)==rule.dst_port);
	}
	// packet is TCP
	if (rule.protocol==PROT_UDP){
		return (skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_UDP)&&
		(ntohs(udp_hdr(skb)->source)==rule.src_port)&&(ntohs(udp_hdr(skb)->dest)==rule.dst_port);
	}
    return 1;
}

int check_ack(struct sk_buff *skb, rule_t rule){
	if ((skb->protocol == htons(ETH_P_IP))&&(ip_hdr(skb)->protocol==IPPROTO_TCP)) { 
		// check_port already checked that the packet is tcp
        return ((tcp_hdr(skb)->ack)&&(rule.ack==ACK_YES))||((!tcp_hdr(skb)->ack)&&(rule.ack==ACK_NO))||(rule.ack==ACK_ANY);
    }
	return 1;
}

/*
Logging functions
*/

static int compare_logs(log_row_t *log1, log_row_t *log2){
	//compare log rows by all parameters except time and reason
	if (!((log1->protocol==log2->protocol)&&(log1->action==log2->action)&&
    (log1->src_ip==log2->src_ip)&&(log1->dst_ip==log2->dst_ip)&&(log1->src_port==log2->src_port)&&
    (log1->dst_port==log2->dst_port))){
		return 0;
	}
	//reason -1 marks a log of a packet compared to conn table- in that case no need to check reason
	if ((log1->reason==-1)&&(log2->reason==-1)){
		return 1;
	}
	return ((log1->reason)==(log2->reason));
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

//create log_row_t element for table by combined data from the rule and from the packet
log_row_t log_by_protocol(__u8 protocol, struct sk_buff *skb, int reason, unsigned char action){
	log_row_t log;
	if (protocol==IPPROTO_TCP){
		log = (log_row_t){get_time(), PROT_TCP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, tcp_hdr(skb)->source,
		tcp_hdr(skb)->dest, reason, 0};
	}
	else if (protocol==IPPROTO_UDP){
		log = (log_row_t){get_time(), PROT_UDP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, udp_hdr(skb)->source,
		udp_hdr(skb)->dest, reason, 0};
	}
	else{
		log = (log_row_t){get_time(), PROT_ICMP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, 0,
		0, reason, 0};
	}
	return log;
}

//main log function- called from hook
//special_reason>0 iff there is a special reason for drop verdict in this log
void log(rule_t *rule, struct sk_buff *skb, int rule_table_idx, int special_reason){
	log_row_t *log = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_KERNEL);
	int reason = rule_table_idx;
	unsigned char action;
	struct net_device *dev = skb->dev;
	if (strcmp(dev->name, "lo")==0){
		//no log in case of loopback
		return;
	}
	//handle special cases of dropping packets (empty table, no rule found, wrong direction, xmas packet):
	if (special_reason>0){
		reason = find_special_reason(special_reason);
		action = NF_DROP;
	}
	else {
		action = rule->action;
	}
	//don't log non-IP packets
	if (skb->protocol != htons(ETH_P_IP)){
		return; 
	}
	//create log_row_t element for logging:
	*log = log_by_protocol(ip_hdr(skb)->protocol, skb, reason, action);
	//change the table according to exist\new log:
	exist_log_check(log);
}

/*
find match rules function
*/
int search_match_rule_and_log(struct sk_buff *skb){
	int rule_table_idx;
	for (rule_table_idx = 0; rule_table_idx<*rule_table_size; rule_table_idx++){
		rule_t curr_rule= rule_table[rule_table_idx];
		if (check_direction(skb, curr_rule)&&check_ip(skb, curr_rule)&&check_protocol_and_port(skb,curr_rule)&&check_ack(skb, curr_rule)){
			log(&curr_rule, skb, rule_table_idx, 0);
			return curr_rule.action;
		}
	}
	//no matching rule found:
	log(NULL, skb, 0, 2);
	return NF_DROP; 
}

/*
connection table functions
*/

//set up the transitions of the state machine to the tcp connection state table
void initialize_by_rules(void){
	int rule_idx;
	for (rule_idx = 0; rule_idx < TCP_RULES_AMOUNT; rule_idx++) {
        tcp_states_table[rules_priv_state[rule_idx]][rules_packs_flags[rule_idx]] = rules_next_state_rule[rule_idx];
	}
}

//receive a flag number and initialize the table by packet direction and state category list
void initialize_by_flags_int(int packet_flags){
	int priv_rule_idx;
	//packet from client to server:
	if (packet_flags & 0) {
		for (priv_rule_idx = 0; priv_rule_idx < CLIENT_PACK_ONLY_STATES; priv_rule_idx++) { 
			tcp_states_table[client_packs_only_states[priv_rule_idx]][packet_flags] = client_packs_only_states[priv_rule_idx];
		}
		for (priv_rule_idx = 0; priv_rule_idx < SERVER_PACKS_ONLY_STATES; priv_rule_idx++) { 
			tcp_states_table[server_packs_only_states[priv_rule_idx]][packet_flags] = -1;
		}
	}
	//packet from server to client:
	if (packet_flags & 1){
		for (priv_rule_idx = 0; priv_rule_idx < SERVER_PACKS_ONLY_STATES; priv_rule_idx++) { 
			tcp_states_table[server_packs_only_states[priv_rule_idx]][packet_flags] = server_packs_only_states[priv_rule_idx];
		}
		for (priv_rule_idx = 0; priv_rule_idx < CLIENT_PACK_ONLY_STATES; priv_rule_idx++) { 
			tcp_states_table[client_packs_only_states[priv_rule_idx]][packet_flags] = -1;
		}
	}
	//doesn't matter if the packet is from server or from client:
	for (priv_rule_idx = 0; priv_rule_idx < BOTH_PACK_STATES; priv_rule_idx++) { 
		tcp_states_table[both_packs_only_states[priv_rule_idx]][packet_flags] = both_packs_only_states[priv_rule_idx];
	}
	tcp_states_table[neither_packet_state][packet_flags] = -1;
}

//set up the tcp states transition table
void initialize_tcp_states_table(void) {
	int packet_flags;
	//first set up the default 
	for (packet_flags = 0; packet_flags < TCP_STATES_TABLE_COLS; packet_flags++) {
		initialize_by_flags_int(packet_flags);
    }
	//finally set up the transitions of the state machine
	initialize_by_rules();
}

//create the flags int from the flags in the packet tcp header and the direction (client to server\server to client) of the packet
int create_flags_int(int syn, int ack, int fin, client_server_t client_server) {
    int flags_int = 0;
    flags_int |= syn;
    flags_int |= ack << 1;
    flags_int |= fin << 2;
    flags_int |= client_server << 3;
    return flags_int;
}

state_t decide_next_state(state_t curr_state, struct sk_buff *skb, client_server_t client_server){
	struct tcphdr *tcp_header = tcp_hdr(skb);
	return tcp_states_table[curr_state][create_flags_int(tcp_header->syn, tcp_header->ack, tcp_header->fin, client_server)];
}

conn_row_t *buff_to_conn(struct sk_buff *skb, state_t next_state){
	conn_row_t *conn = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	*conn = (conn_row_t){ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, tcp_hdr(skb)->source, tcp_hdr(skb)->dest, next_state, CLIENT_TO_SERVER};
	return conn;
}

conn_row_t *buff_to_conn_reverse(struct sk_buff *skb, state_t next_state){
	conn_row_t *conn = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	*conn = (conn_row_t){ip_hdr(skb)->daddr, ip_hdr(skb)->saddr, tcp_hdr(skb)->dest, tcp_hdr(skb)->source, next_state, SERVER_TO_CLIENT};
	return conn;
}

void add_to_conn_table(struct sk_buff *skb, unsigned int rule_decision, state_t next_state){
	if (rule_decision==NF_ACCEPT){ //ack==0 and reason is rule
		add_to_conn_list(buff_to_conn(skb, next_state));
		add_to_conn_list(buff_to_conn_reverse(skb, next_state));
	}
}

int check_match(conn_row_t *row_for_check_match, conn_row_t *current_row_check){
	return ((row_for_check_match->src_ip==current_row_check->src_ip)&&(row_for_check_match->dst_ip==current_row_check->dst_ip)&&
			(row_for_check_match->src_port==current_row_check->src_port)&&(row_for_check_match->dst_port==current_row_check->dst_port));
}

//in case of receiving a packet from a connection is state STATE_TIME_WAIT- update state if needed (decide by timeout)
void exit_state_time_wait(state_t curr_state, conn_row_t *match_row_found, conn_row_t *match_row_found_reverse){
	long curr_sec_time;
	if (curr_state==STATE_TIME_WAIT){
		curr_sec_time = get_time();
		if (curr_sec_time-match_row_found->timestamp>TIMEOUT){
			match_row_found->state = STATE_CLOSED;
			match_row_found->state = STATE_CLOSED;
		}
	}
}

//update timestamp in case of new state time wait so we can change it to STATE_CLOSE later
void set_state_time_wait(state_t next_state, conn_row_t *match_row_found, conn_row_t *match_row_found_reverse){
	long curr_sec_time;
	if (next_state==STATE_TIME_WAIT){
		curr_sec_time = get_time();
		match_row_found->timestamp = curr_sec_time;
		match_row_found_reverse->timestamp = curr_sec_time;
	}
}

//update the state of the connection in the connection table and return the decision which enforce the tcp state machine rules
int update_state_and_decide(conn_row_t *match_row_found, conn_row_t *match_row_found_reverse, struct sk_buff *skb){
	state_t curr_state = match_row_found->state;
	state_t next_state;
	//in case of receiving a packet from a connection is state STATE_TIME_WAIT- update state if needed:
	exit_state_time_wait(curr_state, match_row_found, match_row_found_reverse);
	next_state = decide_next_state(curr_state, skb, match_row_found->client_server);
	if (next_state==-1){
		return -1;
	}
	//update timestamp in case of new state time wait so we can change it to STATE_CLOSE later
	set_state_time_wait(next_state, match_row_found, match_row_found_reverse);
	match_row_found->state = next_state;
	match_row_found_reverse->state = next_state;
	return NF_ACCEPT;
}

//search the connection table for matching connection rows for the packet and the opposite direction connection
int search_conn_table(struct sk_buff *skb){
	conn_row_t *match_row_found; //the connection row in table the matches the packets' data
	conn_row_t *match_row_found_reverse; //the connection row in table that matches the packets' data in the opposite direction
	conn_row_t *row_for_check_match = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	conn_row_t *row_for_check_match_reverse = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	//find the match and reverse match rows by a comparing function on the relevant data:
	*row_for_check_match = (conn_row_t){ip_hdr(skb)->daddr, ip_hdr(skb)->saddr, tcp_hdr(skb)->dest, tcp_hdr(skb)->source, 0, 0};
	match_row_found = find_identical_conn(row_for_check_match, check_match);
	if (match_row_found==NULL){
		return -1;
	}
	*row_for_check_match_reverse = (conn_row_t){ip_hdr(skb)->daddr, ip_hdr(skb)->saddr, tcp_hdr(skb)->dest, tcp_hdr(skb)->source, 0, 0};
	match_row_found_reverse = find_identical_conn(row_for_check_match_reverse, check_match);
	kfree(row_for_check_match);
	kfree(row_for_check_match_reverse);
	return update_state_and_decide(match_row_found, match_row_found_reverse, skb);
}

// when ack=1 there should be a connection row relevant to the table- decide drop/forward based on the match from the table
unsigned int handle_packet_ack_1(struct sk_buff *skb){
	int search_conn_table_result = search_conn_table(skb);
	if (search_conn_table_result==-1){ //in case no existing connection match found
		log(NULL, skb, 0, 1);
		return NF_DROP;
	}
	//normal log, but with no rule base on:
	//rule_table_indx=-1 means accept cause of connection table decision
	log(NULL, skb, -1, 0); 
	return search_conn_table_result;
}

// when ack=0 this packet should be the first packet sent in this connection
// decide and add add it to the table in case of accept verdict
unsigned int handle_packet_ack_0(struct sk_buff *skb){
	int search_conn_table_result = search_conn_table(skb);
	int next_state;
	unsigned int decision_by_rules;
	//in case there is a connection with the packet's data and it is closed (the tcp state transition table enforce this):
	if (search_conn_table_result!=-1){
		return search_conn_table_result;
	}
	//find the first state- initialize with STATE_CLOSED
	next_state = decide_next_state(STATE_CLOSED, skb, CLIENT_TO_SERVER); 
	if (next_state==-1){
		log(NULL, skb, 0, 1);
		return NF_DROP;
	}
	//this is the first packet- so decide based on the rule table (and log)
	decision_by_rules = search_match_rule_and_log(skb);
	if (decision_by_rules==NF_ACCEPT){
		add_to_conn_table(skb, decision_by_rules, next_state);
	}
	return decision_by_rules;
}

//decide forward/drop the packet based on the connection table and log
unsigned int handle_tcp_by_conn(struct sk_buff *skb){
	// when ack=1 there should be a connection row relevant to the table- decide drop/forward based on the match from the table
	if (tcp_hdr(skb)->ack){
		return handle_packet_ack_1(skb);
	}
	// when ack=0 this packet should be the first packet sent in this connection
	// decide and add add it to the table in case of accept verdict
	else{
		return handle_packet_ack_0(skb);
	}
}


/*
The hook function of the firewall:
*/
unsigned int hookfn_by_rule_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	if (skb==NULL){
		log(NULL, skb, 0, 1);
		return NF_DROP;
	}
	if (check_xmas_tree_packet(skb)){
		log(NULL, skb, 0, 4);
		return NF_DROP;
	}
	if (is_tcp_packet(skb)){
		return handle_tcp_by_conn(skb);
	}
	if (*rule_table_size==0){
		printk(KERN_INFO "writing reason 3 log\n");
		log(NULL, skb, 0, 3);
	}
	return search_match_rule_and_log(skb);
}

int register_hook(rule_t *input_rule_table, int *input_rule_table_size){
	init_log_list();
	initialize_tcp_states_table();
	rule_table = input_rule_table;
	rule_table_size = input_rule_table_size;
	by_table_nh_ops.hook = &hookfn_by_rule_table;
	by_table_nh_ops.pf = PF_INET;
	by_table_nh_ops.hooknum = NF_INET_PRE_ROUTING;
	by_table_nh_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &by_table_nh_ops);
}

void unregister_hook(void){
    nf_unregister_net_hook(&init_net, &by_table_nh_ops);
}
