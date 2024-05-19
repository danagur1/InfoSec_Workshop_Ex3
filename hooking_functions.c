#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <linux/types.h>
#include "fw.h"
#include "manage_log_list.h"
#include "manage_conn_list.h"
#include "proxy.h"

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

static struct nf_hook_ops by_table_nf_ops;
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
		return is_tcp_packet(skb)&&((ntohs(tcp_hdr(skb)->source)==rule.src_port)||(rule.src_port==0))&&
		((ntohs(tcp_hdr(skb)->dest)==rule.dst_port)||(rule.src_port==0));
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

//create log_row_t element for table by combined data from the rule and from the packet
log_row_t log_by_protocol(__u8 protocol, struct sk_buff *skb, int reason, unsigned char action){
	log_row_t log;
	if (protocol==IPPROTO_TCP){
		log = (log_row_t){get_time(), PROT_TCP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, tcp_hdr(skb)->source,
		ntohs(tcp_hdr(skb)->dest), reason, 0};
	}
	else if (protocol==IPPROTO_UDP){
		log = (log_row_t){get_time(), PROT_UDP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, udp_hdr(skb)->source,
		ntohs(udp_hdr(skb)->dest), reason, 0};
	}
	else{
		log = (log_row_t){get_time(), PROT_ICMP, action, ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, 0,
		0, reason, 0};
	}
	return log;
}

//main log function- called from hook
//in case of error return -2, else return 0
int log(rule_t *rule, struct sk_buff *skb, int reason){
	log_row_t *log = (log_row_t*)kmalloc(sizeof(log_row_t), GFP_KERNEL);
	unsigned char action;
	struct net_device *dev = skb->dev;
	if (!log){
		return -2;
	}
	if (strcmp(dev->name, "lo")==0){
		//no log in case of loopback
		return 0;
	}
	//handle special cases of dropping packets (empty table, no rule found, wrong direction, xmas packet):
	if (reason<0){
		action = NF_DROP;
	}
	else {
		if (rule==NULL){ //means this log determinated by connection table
			action = NF_ACCEPT;
		}
		else{
			action = rule->action;
		}
	}
	//don't log non-IP packets
	if (skb->protocol != htons(ETH_P_IP)){
		return 0; 
	}
	//create log_row_t element for logging:
	*log = log_by_protocol(ip_hdr(skb)->protocol, skb, reason, action);
	//change the table according to exist\new log:
	exist_log_check(log);
	return 0;
}

/*
find match rules function
in case of error return -2
in case the verdict is ACCEPT- return the reason (the index of the rule that accepted)
else- retrurn -1
*/
int search_match_rule_and_log(struct sk_buff *skb){
	int rule_table_idx;
	for (rule_table_idx = 0; rule_table_idx<*rule_table_size; rule_table_idx++){
		rule_t curr_rule= rule_table[rule_table_idx];
		if (check_direction(skb, curr_rule)&&check_ip(skb, curr_rule)&&check_protocol_and_port(skb,curr_rule)&&check_ack(skb, curr_rule)){
			if (log(&curr_rule, skb, rule_table_idx)==-2){ //error check
				return -2;
			}
			if (curr_rule.action==NF_ACCEPT){
				return rule_table_idx;
			}
			else{
				return -1;
			}
		}
	}
	//no matching rule found:
	if (log(NULL, skb, REASON_NO_MATCHING_RULE)==-2){
		return -2;
	}
	return -1; 
}

//treanslates the output of search_match_rule_and_log to accept/drop
unsigned int search_result_to_verdict(int search_decison){
	if (search_decison==-1){
		return NF_DROP;
	}
	else{
		return NF_ACCEPT;
	}
}

/*
connection table functions
*/

//set up the transitions of the state machine to the tcp connection state table
void initialize_by_rules(void){
	int rule_idx;
	for (rule_idx = 0; rule_idx < TCP_RULES_AMOUNT; rule_idx++) {
		printk(KERN_INFO "ininitialize_by_rules  tcp_states_table[%d][%d]=%d\n", rules_priv_state[rule_idx], rules_packs_flags[rule_idx],
		rules_next_state_rule[rule_idx]);
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
    int flags_int = syn << 3 | ack << 2 | fin << 1 | client_server;
	printk(KERN_INFO "in create_flags_int with syn=%d, ack=%d, fin=%d client_server=%d and flags_int=%d\n", syn, ack, fin, 
	client_server, flags_int);
    return flags_int;
}

state_t decide_next_state(state_t curr_state, struct sk_buff *skb, client_server_t client_server){
	struct tcphdr *tcp_header = tcp_hdr(skb);
	state_t next_state = tcp_states_table[curr_state][create_flags_int(tcp_header->syn, tcp_header->ack, tcp_header->fin, 
	client_server)];
	printk("in decide_next_state with curr_state=%d, create_flags_int=%d, next state=%d %d\n", 
	curr_state, create_flags_int(tcp_header->syn, tcp_header->ack, tcp_header->fin, client_server),
	tcp_states_table[curr_state][create_flags_int(tcp_header->syn, tcp_header->ack, tcp_header->fin, client_server)], next_state);
	printk("returning to update_state and decide with %d\n", next_state);
	return next_state;
}

conn_row_t *buff_to_conn(struct sk_buff *skb, state_t next_state, unsigned int reason){
	conn_row_t *conn = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	if (!conn){
		return NULL;
	}
	*conn = (conn_row_t){ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, ntohs(tcp_hdr(skb)->source), ntohs(tcp_hdr(skb)->dest), next_state, 
	CLIENT_TO_SERVER, 0, reason, 0, 0};
	printk("in buff_to_conn dst port %d, client_to_server %d\n", conn->dst_port, CLIENT_TO_SERVER);
	return conn;
}

conn_row_t *buff_to_conn_reverse(struct sk_buff *skb, state_t next_state, unsigned int reason){
	conn_row_t *conn = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	if (!conn){
		return NULL;
	}
	*conn = (conn_row_t){ip_hdr(skb)->daddr, ip_hdr(skb)->saddr, ntohs(tcp_hdr(skb)->dest), ntohs(tcp_hdr(skb)->source), next_state, SERVER_TO_CLIENT, 0, reason, 0, 0};
	printk("in buff_to_conn dst port %d, client_to_server %d\n", conn->dst_port, SERVER_TO_CLIENT);
	return conn;
}

//creates a new line in the connection table accoreding to the data of the packet, the state and the reason
//return -2 on error, else 0
int add_to_conn_table(struct sk_buff *skb, state_t next_state, unsigned int reason){
	conn_row_t *conn = buff_to_conn(skb, next_state, reason);
	conn_row_t *conn_reverse;
	if (conn==NULL){
		return -2;
	}
	conn_reverse = buff_to_conn_reverse(skb, next_state, reason);
	if (conn_reverse==NULL){
		kfree(conn);
		return -2;
	}
	printk(KERN_INFO "checking addition1. in add_to_conn_table before 1st addition. port=%d\n", conn->src_port);
	add_to_conn_list(conn);	
	printk(KERN_INFO "checking addition1. in add_to_conn_table before 2nd addition. port=%d\n", conn_reverse->src_port);
	add_to_conn_list(conn_reverse);
	return 0;
}

int check_match(conn_row_t *row_for_check_match, conn_row_t *current_row_check){
	int result = ((row_for_check_match->src_ip==current_row_check->src_ip)&&(row_for_check_match->dst_ip==current_row_check->dst_ip)&&
			(row_for_check_match->src_port==current_row_check->src_port)&&(row_for_check_match->dst_port==current_row_check->dst_port));
	if (result==1){
		printk(KERN_INFO "in check_match from table src ip %d, dst ip %d src port %d, dst port %d and found client server %d\n", 
		row_for_check_match->src_ip, row_for_check_match->dst_ip, row_for_check_match->src_port, row_for_check_match->dst_port,
		row_for_check_match->client_server);
		printk(KERN_INFO "in check_match my element src ip %d, dst ip %d src port %d, dst port %d and found client server %d\n", 
		current_row_check->src_ip, current_row_check->dst_ip, current_row_check->src_port, current_row_check->dst_port,
		current_row_check->client_server);
	}
	return result;
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
//in case of invalid packet: return -1, else: return the reason of the match to the packet from the table
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
	return 0; //match_row_found->reason;
}

int search_conn_table_logic(struct sk_buff *skb, conn_row_t **match_row_found, conn_row_t **match_row_found_reverse)
{
	conn_row_t *row_for_check_match_reverse;
	conn_row_t *row_for_check_match = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	if (!row_for_check_match){
		return -2;
	}
	row_for_check_match_reverse = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	if (!row_for_check_match_reverse){
		kfree(row_for_check_match);
		return -2;
	}
	//find the match and reverse match rows by a comparing function on the relevant data:
	*row_for_check_match = (conn_row_t){ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, ntohs(tcp_hdr(skb)->source), ntohs(tcp_hdr(skb)->dest), STATE_CLOSED, CLIENT_TO_SERVER, 0, 0, 0, 0};
	*match_row_found = find_identical_conn(row_for_check_match, check_match);
	if (*match_row_found==NULL){
		return -1;
	}
	*row_for_check_match_reverse = (conn_row_t){ip_hdr(skb)->daddr, ip_hdr(skb)->saddr, ntohs(tcp_hdr(skb)->dest), ntohs(tcp_hdr(skb)->source), STATE_CLOSED, CLIENT_TO_SERVER, 0, 0, 0, 0};
	*match_row_found_reverse = find_identical_conn(row_for_check_match_reverse, check_match);
	kfree(row_for_check_match);
	kfree(row_for_check_match_reverse);
	return 0;
}


//search the connection table for matching connection rows for the packet and the opposite direction connection- return the verdict
//in case of error return -2, in case of invalid packet: return -1, else: return the reason of the match found
int search_conn_table(struct sk_buff *skb){
	conn_row_t *match_row_found; //the connection row in table the matches the packets' data
	conn_row_t *match_row_found_reverse; //the connection row in table that matches the packets' data in the opposite direction
	int logic_result = search_conn_table_logic(skb, &match_row_found, &match_row_found_reverse);
	if (logic_result<0){
		return logic_result;
	}
	return update_state_and_decide(match_row_found, match_row_found_reverse, skb);
}

//same function as search_conn_table but also saves the client_server value in the input pointer
int search_conn_table_save(struct sk_buff *skb, client_server_t *save_client_server, state_t *save_state){
	conn_row_t *match_row_found; //the connection row in table the matches the packets' data
	conn_row_t *match_row_found_reverse; //the connection row in table that matches the packets' data in the opposite direction
	int logic_result = search_conn_table_logic(skb, &match_row_found, &match_row_found_reverse);
	if (logic_result<0){
		return logic_result;
	}
	//pass the values of match client server and state (berfore changing it) for decision making related to proxy
	*save_client_server = match_row_found->client_server;
	*save_state = match_row_found->state;
	return update_state_and_decide(match_row_found, match_row_found_reverse, skb);
}

// when ack=1 there should be a connection row relevant to the table- decide drop/forward based on the match from the table
unsigned int handle_packet_ack_1(struct sk_buff *skb, client_server_t *save_client_server, state_t *save_state){
	int reason = search_conn_table_save(skb, save_client_server, save_state);
	printk(KERN_INFO "in handle_packet_ack_1\n");
	if (reason==-2){ //error check
		return NF_DROP;
	}
	if (reason==-1){ //in case no existing connection match found
		log(NULL, skb, REASON_ILLEGAL_VALUE); //in case of error still return NF_DROP
		return NF_DROP;
	}
	if (log(NULL, skb, reason)==-2){ //error check
		return NF_DROP;
	};
	return NF_ACCEPT;
}

// when ack=0 this packet should be the first packet sent in this connection
// decide and add add it to the table in case of accept verdict
unsigned int handle_packet_ack_0(struct sk_buff *skb){
	int search_conn_table_result = search_conn_table(skb);
	int next_state;
	int search_result;
	printk(KERN_INFO "in handle_packet_ack_0\n");
	//in case there is a connection with the packet's data and it is closed (the tcp state transition table enforce this):
	//printk("in handle_packet_ack_0 with search result %d\n", search_conn_table_result);
	if (search_conn_table_result==-2){ //error check
		printk("in handle_packet_ack_0 drop1\n");
		return NF_DROP;
	}
	if (search_conn_table_result!=-1){
		printk("in handle_packet_ack_0 return2\n");
		return search_conn_table_result;
	}
	//find the first state- initialize with STATE_CLOSED
	next_state = decide_next_state(STATE_CLOSED, skb, CLIENT_TO_SERVER); 
	if (next_state==-1){
		log(NULL, skb, REASON_ILLEGAL_VALUE); //in case of error still return NF_DROP
		printk("in handle_packet_ack_0 drop3\n");
		return NF_DROP;
	}
	//this is the first packet- so decide based on the rule table (and log)
	search_result = search_match_rule_and_log(skb);
	if (search_result==-2){ //error check
		printk("in handle_packet_ack_0 drop4\n");
		return NF_DROP;
	}
	//in case of accept verdict- the result is the reason (the index of the rule that had match in the table)
	if (search_result==-1){
		printk("in handle_packet_ack_0 drop5\n");
		return NF_DROP;
	}
	else{
		if (add_to_conn_table(skb, next_state, (unsigned int)search_result)==-2){
			printk("in handle_packet_ack_0 drop6\n");
			return NF_DROP;
		}
		printk("in handle_packet_ack_0 return7\n");
		printk("added a new conn row with next_state=%d\n", next_state);
		return NF_ACCEPT;
	}
}

//decide forward/drop the packet based on the connection table and log
unsigned int handle_tcp_by_conn(struct sk_buff *skb){
	unsigned int verdict;
	client_server_t client_server;
	state_t state;
	int first_packet = 0;
	printk(KERN_INFO "in handle_tcp_by_conn");
	//printk("in handle_tcp_by_conn- received a packet with src ip= %d\n", (ip_hdr(skb)->saddr));
	// when ack=1 there should be a connection row relevant to the table- decide drop/forward based on the match from the table
	if (tcp_hdr(skb)->ack){
		verdict = handle_packet_ack_1(skb, &client_server, &state);
	}
	// when ack=0 this packet should be the first packet sent in this connection
	// decide and add add it to the table in case of accept verdict
	else{
		verdict = handle_packet_ack_0(skb);
		client_server = CLIENT_TO_SERVER;
		printk("after handle_packet_ack_0 and verdict==NF_ACCEPT=%d\n", verdict==NF_ACCEPT);
		first_packet = 1;
	}
	printk(KERN_INFO "in handle_tcp_by_conn and verdict==NF_ACCEPT%d\n", verdict==NF_ACCEPT);
	if ((verdict==NF_ACCEPT)){
		printk(KERN_INFO "calling proxy_pre with first_packet=%d\n", first_packet);
		if (proxy_pre(skb, client_server)==-1){ //error check
			return NF_DROP;
		}
	}
	return verdict;
}

/*
The hook function of the firewall:
*/
unsigned int hookfn_by_rule_table(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
	int search_result;
	int return_result;
	if (skb==NULL){
		log(NULL, skb, REASON_ILLEGAL_VALUE); //in case of error still return error drop
		return NF_DROP;
	}
	if (check_xmas_tree_packet(skb)){
		log(NULL, skb, REASON_XMAS_PACKET); //in case of error still return error drop
		return NF_DROP;
	}
	if (is_tcp_packet(skb)){
		printk(KERN_INFO "in hookfn_by_rule_table tcp src IP= %pI4, dst IP=%pI4 src port=%d, dest port=%d, syn=%d, ack=%d\n", &(ip_hdr(skb)->saddr),
		&(ip_hdr(skb)->daddr), ntohs(tcp_hdr(skb)->source), ntohs(tcp_hdr(skb)->dest), tcp_hdr(skb)->syn, tcp_hdr(skb)->ack);
		return_result = handle_tcp_by_conn(skb);
		printk(KERN_INFO "a tcp packet is leaving- src IP %pI4 dst IP %pI4 src port %d dst port %d and accept=%d, drop=%d\n", &(ip_hdr(skb)->saddr), &(ip_hdr(skb)->daddr), 
        ntohs(tcp_hdr(skb)->source), ntohs(tcp_hdr(skb)->dest),return_result==NF_ACCEPT, return_result==NF_DROP);
		return return_result;
	}
	return NF_ACCEPT;
	if (*rule_table_size==0){
		if (log(NULL, skb, REASON_FW_INACTIVE)==-2){ //error check
			return NF_DROP;
		}
	}
	search_result = search_match_rule_and_log(skb);
	if (search_result==-2){ //error check
		return NF_DROP;
	}
	return search_result_to_verdict(search_result);
}

int register_hook_pre(rule_t *input_rule_table, int *input_rule_table_size){
	printk(KERN_INFO "start");
	init_log_list();
	init_conn_list();
	initialize_tcp_states_table();
	rule_table = input_rule_table;
	rule_table_size = input_rule_table_size;
	by_table_nf_ops.hook = &hookfn_by_rule_table;
	by_table_nf_ops.pf = PF_INET;
	by_table_nf_ops.hooknum = NF_INET_PRE_ROUTING;
	by_table_nf_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &by_table_nf_ops);
}

void unregister_hook_pre(void){
	remove_all_from_conn_list();
	remove_all_from_log_list();
    nf_unregister_net_hook(&init_net, &by_table_nf_ops);
}
