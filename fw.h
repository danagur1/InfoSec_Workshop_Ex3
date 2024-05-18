#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>



// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_CLEAR_LOG		"log"
#define DEVICE_NAME_SHOW_LOG		"fw_log"
#define DEVICE_NAME_SHOW_CONN		"conns"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES			= 0,
	MINOR_LOG_SHOW      = 1,
	MINOR_LOG_CLEAR		= 2,
	MINOR_CONN_SHOW		= 3,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

typedef enum {
	//STATE_STATE1_TO_STATE2 = after part of the transition between states completed, but not all of it
	STATE_CLOSED            			= 0,
	STATE_CLOSED_TO_SYN_RECEIVED		= 1,
	STATE_SYN_SENT          			= 2,
	STATE_SYN_SENT_TO_SYN_RECEIVED		= 3,
	STATE_SYN_SENT_TO_ESTABLISHED		= 4, 
    STATE_SYN_RECEIVED      			= 5,
    STATE_ESTABLISHED       			= 6,
	STATE_ESTABLISHED_TO_CLOSE_WAIT		= 7,
    STATE_CLOSE_WAIT        			= 8,
    STATE_LAST_ACK          			= 9,
    STATE_FIN_WAIT_1        			= 10,
	STATE_FIN_WAIT_1_TO_CLOSING			= 11,
    STATE_FIN_WAIT_2        			= 12,
	STATE_FIN_WAIT_2_TO_TIME_WAIT		= 13,
    STATE_CLOSING           			= 14,
    STATE_TIME_WAIT         			= 15,
} state_t;

typedef enum {
	CLIENT_TO_SERVER = 0,
	SERVER_TO_CLIENT = 1,
} client_server_t;

typedef struct {
	__be32   		src_ip;
	__be32			dst_ip;
	__be16 			src_port;
	__be16 			dst_port;
	state_t     	state;
	client_server_t client_server; 
	//client_server=CLIENT_TO_SERVER if this line represents packets sent from client to server, 
	//client_server=SERVER_TO_CLIENT if this line represents packets sent from server to client
	unsigned long  	timestamp;
	int				reason;
	__be16			proxy_port_http;
	__be16			proxy_port_ftp;
} conn_row_t;

#endif // _FW_H_
