#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include "fw.h"
#include "manage_conn_list.h"
#define FW_IP  50397450//10.1.1.3 IP as 32bit number

static struct nf_hook_ops proxy_lout_nf_ops;

int modify_hex_digits(int num) {
    int second_digit = (num >> 8) & 0xF;
    int last_digit = num & 0xF;
    
    second_digit = (second_digit + 1) & 0xF;
    last_digit = (last_digit - 1) & 0xF;
    
    return (num & ~(0xF0F)) | (second_digit << 8) | last_digit;
}

void fix_transport_checksum(struct sk_buff *skb,struct iphdr *ip_header, struct tcphdr *tcp_header) {
    int tcplen;
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

    skb->ip_summed = CHECKSUM_NONE;
    skb->csum_valid = 0;

    /* Linearize the skb */
    if (skb_linearize(skb) < 0) {
        // Handle error
    }

    /* Re-take headers. The linearize may change skb's pointers */
    ip_header = ip_hdr(skb);
    tcp_header = tcp_hdr(skb);

    /* Fix TCP header checksum */
    tcplen = (ntohs(ip_header->tot_len) - ((ip_header->ihl) << 2));
    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));
    
}

int proxy_pre(struct sk_buff *skb, client_server_t client_server){
    __be32 fw_ip = FW_IP;
    __be16 dst_port = ntohs(tcp_hdr(skb)->dest);
    __be16 src_port = ntohs(tcp_hdr(skb)->source);
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    printk(KERN_INFO "called proxy_pre with ntohs(tcp_hdr(skb)->dest)=%d, match_row_found->client_server=%d\n", 
    ntohs(tcp_hdr(skb)->dest), client_server);
    printk(KERN_INFO "in proxy_pre with client_server=%d and tcp_hdr(skb)->dest=%d\n",client_server,  dst_port);
    if ((client_server==CLIENT_TO_SERVER)&&(dst_port==90)){
        ip_header = ip_hdr(skb);
        tcp_header = tcp_hdr(skb);
        ip_hdr(skb)->daddr = fw_ip;
        tcp_hdr(skb)->dest = htons(800);
        printk(KERN_INFO "proxy pre finished\n");
    }
    else if ((client_server==CLIENT_TO_SERVER)&&(dst_port==21)){
        ip_header = ip_hdr(skb);
        tcp_header = tcp_hdr(skb);
        ip_hdr(skb)->daddr = fw_ip;
        tcp_hdr(skb)->dest = htons(210);
    }
    else if ((client_server==SERVER_TO_CLIENT)&&((src_port==21)||(src_port==90))){
        ip_header = ip_hdr(skb);
        tcp_header = tcp_hdr(skb);
        ip_hdr(skb)->daddr = fw_ip;
    }
    fix_transport_checksum(skb, ip_header, tcp_header);
    return 0;
}

int check_match_proxy_port(conn_row_t *row_for_check_match, conn_row_t *current_row_check){
    return (((row_for_check_match->proxy_port_http==current_row_check->proxy_port_http) ||
            (row_for_check_match->proxy_port_ftp==current_row_check->proxy_port_ftp))&&
            (row_for_check_match->client_server==current_row_check->client_server));
}

conn_row_t *get_match_conn(__be16 proxy_port){
    conn_row_t *row_for_check_match = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
    conn_row_t *match_row_found;
    *row_for_check_match = (conn_row_t){0, 0, 0, 0, CLIENT_TO_SERVER, 0, 0, 0, proxy_port, proxy_port};
	match_row_found = find_identical_conn(row_for_check_match, check_match_proxy_port);
    kfree(row_for_check_match);
    return match_row_found;
}

int check_match_handshake(conn_row_t *row_for_check_match, conn_row_t *current_row_check){
    return ((row_for_check_match->src_ip==current_row_check->src_ip) &&
            (row_for_check_match->src_port==current_row_check->src_port) && 
            (row_for_check_match->client_server==current_row_check->client_server));
}

conn_row_t *get_match_conn_handshake(__be32 client_ip, __be16 client_port){
    conn_row_t *row_for_check_match = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
    conn_row_t *match_row_found;
    *row_for_check_match = (conn_row_t){client_ip, 0, client_port, 0, 0, CLIENT_TO_SERVER, 0, 0, 0, 0};
	match_row_found = find_identical_conn(row_for_check_match, check_match_handshake);
    kfree(row_for_check_match);
    return match_row_found;
}

unsigned int hookfn_lout_proxy(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    conn_row_t *match_row_found;
    printk(KERN_INFO "in hookfn_lout_proxy src IP= %pI4, dst IP=%pI4 src port=%d, dest port=%d\n", &(ip_hdr(skb)->saddr),
	&(ip_hdr(skb)->daddr), ntohs(tcp_hdr(skb)->source), ntohs(tcp_hdr(skb)->dest));
    printk(KERN_INFO "in hookfn_lout_proxy check condition, %d, %d\n", ip_hdr(skb)->saddr==FW_IP, 
    ((ntohs(tcp_hdr(skb)->source)==800)||(ntohs(tcp_hdr(skb)->source)==210)));
    if (ip_hdr(skb)->saddr==FW_IP){
        if ((ntohs(tcp_hdr(skb)->source)==800)||(ntohs(tcp_hdr(skb)->source)==210)){ 
        //a handshake packet- before unique ports where chosen
        //this packet sent from the user space program to the client
        match_row_found = get_match_conn_handshake(ip_hdr(skb)->daddr, ntohs(tcp_hdr(skb)->dest));
        printk("get_match_conn_handshake got NULL %d\n", match_row_found==NULL);
        ip_hdr(skb)->saddr = match_row_found->dst_ip; //set the server address as the source address
        printk(KERN_INFO "just checking- match_row_found->dst_port=%d\n", match_row_found->dst_port);
        tcp_hdr(skb)->source = htons(match_row_found->dst_port); //set the server port as the source port
        }
        else{ 
            //a regular packet from the user space program as part of the MITM process
            //this packet sent from the user spase program to the server
            //we can identify the connection in table by the unique port that the user program chose:
            match_row_found = get_match_conn(ntohs(tcp_hdr(skb)->source));
            printk("get_match_conn got NULL %d\n", match_row_found==NULL);
            return NF_ACCEPT;
            if (match_row_found->client_server==CLIENT_TO_SERVER){
                ip_hdr(skb)->saddr = match_row_found->src_ip; //fake the source address so the server will identify the sender as the client
            }
            else{ //server to client
                ip_hdr(skb)->saddr = match_row_found->src_ip;
                tcp_hdr(skb)->source = htons(match_row_found->src_port);
            }
        }
    }
    fix_transport_checksum(skb, ip_hdr(skb), tcp_hdr(skb));
    printk(KERN_INFO "a packet is leaving lout- src IP %pI4 dst IP %pI4 src port %d dst port %d\n", &(ip_hdr(skb)->saddr), &(ip_hdr(skb)->daddr), 
    ntohs(tcp_hdr(skb)->source), ntohs(tcp_hdr(skb)->dest));
    return NF_ACCEPT; //if the packet is from the user space program- this is part of the MITM process, so accept. Else, don't interrupt it, so also accept
}

int register_hook_lout(void){
	proxy_lout_nf_ops.hook = &hookfn_lout_proxy;
	proxy_lout_nf_ops.pf = PF_INET;
	proxy_lout_nf_ops.hooknum = NF_INET_LOCAL_OUT;
	proxy_lout_nf_ops.priority = NF_IP_PRI_FIRST;
	return nf_register_net_hook(&init_net, &proxy_lout_nf_ops);
}

void unregister_hook_lout(void){
    nf_unregister_net_hook(&init_net, &proxy_lout_nf_ops);
}