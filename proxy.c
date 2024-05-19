#include "fw.h"
#include "manage_conn_list.h"
#define FW_IP  0//10.1.1.3 IP as 32bit number

static struct nf_hook_ops proxy_lout_nf_ops;

unsigned short ip_checksum(void *vdata, size_t length) {
    // Cast the data pointer to one we can index into.
    char *data = (char *)vdata;
    // Initialize the accumulator.
    uint32_t acc = 0xffff;
    // Handle complete 16-bit blocks.
    size_t i;
    uint16_t word;
    for (i = 0; i + 1 < length; i += 2) {
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }
    // Handle any partial block at the end of the data.
    if (length & 1) {
        word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc -= 0xffff;
        }
    }
    // Return the checksum in network byte order.
    return htons(~acc);
}

// Function to update the IP header checksum
void update_ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    iph->check = ip_checksum((void *)iph, iph->ihl * 4);
}

// Function to update the TCP checksum
void update_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    uint16_t tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;
    int pseudo_hdr_len, total_len;
    char *buf;

    // Pseudo header for checksum calculation
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_hdr;
    tcph->check = 0;

    pseudo_hdr.src_addr = iph->saddr;
    pseudo_hdr.dst_addr = iph->daddr;
    pseudo_hdr.placeholder = 0;
    pseudo_hdr.protocol = IPPROTO_TCP;
    pseudo_hdr.tcp_length = htons(tcp_len);

    pseudo_hdr_len = sizeof(struct pseudo_header);
    total_len = pseudo_hdr_len + tcp_len;
    buf = kmalloc(total_len, GFP_KERNEL);

    memcpy(buf, &pseudo_hdr, pseudo_hdr_len);
    memcpy(buf + pseudo_hdr_len, tcph, tcp_len);

    tcph->check = ip_checksum(buf, total_len);

    kfree(buf);
}


void proxy_pre(struct sk_buff *skb, client_server_t client_server){
    __be32 fw_ip = 50397450;
    __be16 dst_port = ntohs(tcp_hdr(skb)->dest);
    __be16 src_port = ntohs(tcp_hdr(skb)->source);
    printk(KERN_INFO "in proxy_pre with client_server=%d and tcp_hdr(skb)->dest=%d",client_server==CLIENT_TO_SERVER,  dst_port);
    if ((client_server==CLIENT_TO_SERVER)&&(dst_port==90)){
        ip_hdr(skb)->daddr = fw_ip;
        tcp_hdr(skb)->dest = htons(800);
        update_ip_checksum(ip_hdr(skb));
        update_tcp_checksum(ip_hdr(skb), tcp_hdr(skb));
        printk(KERN_INFO "proxy pre finished\n");
    }
    else if ((client_server==CLIENT_TO_SERVER)&&(dst_port==21)){
        ip_hdr(skb)->daddr = fw_ip;
        tcp_hdr(skb)->dest = htons(210);
    }
    else if ((client_server==SERVER_TO_CLIENT)&&((src_port==21)||(src_port==90))){
        ip_hdr(skb)->daddr = fw_ip;
    }
}

int check_match_proxy_port(conn_row_t *row_for_check_match, conn_row_t *current_row_check){
    return ((row_for_check_match->proxy_port_http==current_row_check->proxy_port_http) ||
            (row_for_check_match->proxy_port_ftp==current_row_check->proxy_port_ftp));
}

conn_row_t *get_match_conn(__be16 proxy_port){
    conn_row_t *row_for_check_match = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
    conn_row_t *match_row_found;
    *row_for_check_match = (conn_row_t){0, 0, 0, 0, 0, 0, 0, 0, proxy_port, proxy_port};
	match_row_found = find_identical_conn(row_for_check_match, check_match_proxy_port);
    return match_row_found;
}

unsigned int hookfn_lout_proxy(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    conn_row_t *match_row_found;
    printk(KERN_INFO "in hookfn_lout_proxy src IP= %pI4, dst IP=%pI4 src port=%d, dest port=%d\n", &(ip_hdr(skb)->saddr),
	&(ip_hdr(skb)->daddr), ntohs(tcp_hdr(skb)->source), ntohs(tcp_hdr(skb)->dest));
    if ((tcp_hdr(skb)->source==800)||(ntohs(tcp_hdr(skb)->source)==210)){
        //we can identify the connection in table by the unique port that the user program chose:
        match_row_found = get_match_conn(ntohs(tcp_hdr(skb)->source));
        if (match_row_found->client_server==CLIENT_TO_SERVER){
            ip_hdr(skb)->saddr = match_row_found->src_ip; //fake the source address so the server will identify the sender as the client
        }
        else{ //server to client
            ip_hdr(skb)->saddr = match_row_found->src_ip;
            tcp_hdr(skb)->source = htons(match_row_found->src_port);
        }
    }
    return NF_ACCEPT; //if packet is from local out this is part of the MITM process, else don't interrupt it
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