#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "fw.h"
#include "manage_conn_list.h"
#include "hooking_functions.h"

#define RULE_FILEDS 4

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

int ROW_OUTPUT_SIZE = 19;

typedef int (*ParseFieldFuncPointer)(conn_row_t*);
static int major_number;					// Major of the char device
static struct class* devices_class = NULL;	// The device's class
static struct device* conn_device = NULL;	// The device's name
static char *conn_output = NULL;
int position_in_conn_output = 0;
int count_conn = 0;
unsigned int conn_input_buf_index = 0;
const char *conn_input_buf_pointer;

/*
DISPLAY ACTION FUCNTIONS
*/

static void reverse_parse_ip(__le32 *src){
	char *curr_conn_position = conn_output+position_in_conn_output;
	memcpy(curr_conn_position, src, sizeof(__le32));
	position_in_conn_output += sizeof(__le32);
}

static void reverse_parse_port(__le16 *src){
	char *curr_conn_position = conn_output+position_in_conn_output;
	memcpy(curr_conn_position, src, sizeof(__le16));
    position_in_conn_output += sizeof(__le16);
}

static void reverse_parse_state(state_t src){
	char *curr_conn_position = conn_output+position_in_conn_output;
	unsigned char state_byte = (unsigned char)src;
    memcpy(curr_conn_position, &state_byte, 1);
    position_in_conn_output += 1;
}

static void put_validation_conn(char valid_conn){
	conn_output[position_in_conn_output] = valid_conn;
	position_in_conn_output++;
}

static void reverse_parse_client_server(client_server_t src){
	char *curr_conn_position = conn_output+position_in_conn_output;
	unsigned char client_server_byte = (unsigned char)src;
    memcpy(curr_conn_position, &client_server_byte, 1);
    position_in_conn_output += 1;
}

static int print_conn(conn_row_t conn){
	count_conn++;
	put_validation_conn(1); 
	reverse_parse_ip(&(conn.src_ip));
    reverse_parse_ip(&(conn.dst_ip));
    reverse_parse_port(&(conn.src_port));
    reverse_parse_port(&(conn.dst_port));
    reverse_parse_state(conn.state);
	reverse_parse_client_server(conn.client_server);
	reverse_parse_port(&(conn.proxy_port_http));
	reverse_parse_port(&(conn.proxy_port_ftp)); 
	return 0;
}

static ssize_t display(struct device *dev, struct device_attribute *attr, char *buf) {
	int conn_list_length = get_conn_list_length();
	position_in_conn_output = 0;
    count_conn = 0;
	conn_output = (char*)kmalloc(ROW_OUTPUT_SIZE*conn_list_length+1, GFP_KERNEL);
	if (conn_output==NULL){
		return -1;
	}
    func_for_conn_list(print_conn);
	put_validation_conn(0);
	//copy conn_output to buf as a string
	memcpy(buf, conn_output, ROW_OUTPUT_SIZE*conn_list_length);
	kfree(conn_output);
	return ROW_OUTPUT_SIZE*conn_list_length+1;
}

/*
MODIFY ACTION FUCNTIONS
*/

//parsing functions:

static int parse_port(__be16 *dst){
	memcpy(dst, (conn_input_buf_pointer+conn_input_buf_index), sizeof(__le16));
	return sizeof(__le16); //return the length of the parsed element
}

static int parse_src_port(conn_row_t *conn){
	return parse_port(&(conn->src_port));
}

static int parse_dst_port(conn_row_t *conn){
	return parse_port(&(conn->dst_port));
}

static int parse_ip(__be32 *dst){
	memcpy(dst, conn_input_buf_pointer+conn_input_buf_index, sizeof(__be32));
	return sizeof(__be32); //return the length of the parsed element
}

static int parse_src_ip(conn_row_t *conn){
	return parse_ip(&(conn->src_ip));
}

static int parse_dst_ip(conn_row_t *conn){
	return parse_ip(&(conn->dst_ip));
}

static int parse_http_or_ftp(char *dst){
	memcpy(dst, conn_input_buf_pointer+conn_input_buf_index, sizeof(char));
	return sizeof(char);
}

//set the proxy port to the http or ftp proxy port field
void set_proxy_port(conn_row_t *conn_to_set){
	char http_or_ftp;
	__be16 proxy_port;
	conn_input_buf_index += parse_port(&proxy_port);
	parse_http_or_ftp(&http_or_ftp);
	if (http_or_ftp){ //ftp
		conn_to_set->proxy_port_ftp = proxy_port;
	}
	else{ //http
		conn_to_set->proxy_port_http = proxy_port;
	}
}

//main parsing function- uses all the other parsing functions
//parse the input data about the relevant rule and then set its proxy port value
void parse_conn(ParseFieldFuncPointer funcs[], conn_row_t *conn_input){
	int func_idx;
	conn_row_t *conn_input_reverse = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	conn_row_t *conn_match, *conn_match_reverse;
	for (func_idx=0; func_idx< RULE_FILEDS; func_idx++){
		conn_input_buf_index += funcs[func_idx](conn_input)+1;
	}
	conn_match = find_identical_conn(conn_input, check_match);
	conn_input_reverse->src_ip= conn_input->dst_ip;
	conn_input_reverse->dst_ip= conn_input->src_ip;
	conn_input_reverse->src_port= conn_input->dst_port;
	conn_input_reverse->dst_port= conn_input->src_port;
	conn_match_reverse = find_identical_conn(conn_input_reverse, check_match);
	kfree(conn_input_reverse);
	set_proxy_port(conn_match);
}

//sysfs store implementation- parse all the rule componenets from driver
ssize_t conn_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	conn_row_t *conn_input = (conn_row_t*)kmalloc(sizeof(conn_row_t), GFP_KERNEL);
	ParseFieldFuncPointer parse_funcs[] = {parse_src_ip, parse_dst_ip, parse_src_port, parse_dst_port};
	conn_input_buf_index = 0;
	conn_input_buf_pointer = buf;
	parse_conn(parse_funcs, conn_input);
	kfree(conn_input);
	return count;
}

/*
Create and destroy the device related functions:
*/

static struct file_operations fops = { 
	.owner = THIS_MODULE,
};

static DEVICE_ATTR(conns, S_IRUGO, display, conn_modify);

int conn_show_create_dev(struct class *devices_class_input) {
    devices_class = devices_class_input;

	//create char device
	major_number = register_chrdev(0, DEVICE_NAME_SHOW_CONN, &fops);\
	if (major_number < 0) {
		return -1;
	}

	//create sysfs device
	conn_device = device_create(devices_class, NULL, MKDEV(major_number, MINOR_CONN_SHOW), NULL, DEVICE_NAME_SHOW_CONN);	
	if (IS_ERR(conn_device)) {
		class_destroy(devices_class);
		unregister_chrdev(major_number, DEVICE_NAME_SHOW_CONN);
		return -1;
	}

	//create sysfs file attributes	
	if (device_create_file(conn_device, (const struct device_attribute *)&dev_attr_conns.attr))
	{
		device_destroy(devices_class, MKDEV(major_number, MINOR_CONN_SHOW));
		class_destroy(devices_class);
		unregister_chrdev(major_number, DEVICE_NAME_SHOW_CONN);
		return -1;
	}	

	return 0;
}

void conn_show_remove_dev(void) {
	device_remove_file(conn_device, (const struct device_attribute *)&dev_attr_conns.attr);
	device_destroy(devices_class, MKDEV(major_number, MINOR_CONN_SHOW));
	class_destroy(devices_class);
	unregister_chrdev(major_number, DEVICE_NAME_SHOW_CONN);
}
