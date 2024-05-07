#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "fw.h"
#include "manage_conn_list.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

int ROW_OUTPUT_SIZE = 14;

static int major_number;					// Major of the char device
static struct class* devices_class = NULL;	// The device's class
static struct device* conn_device = NULL;	// The device's name
static char *conn_output = NULL;
int position_in_conn_output = 0;
int count_conn = 0;

/*
Parsing and printing functions:
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

static int print_conn(conn_row_t conn){
	count_conn++;
	put_validation_conn(1);
	reverse_parse_ip(&(conn.src_ip));
    reverse_parse_ip(&(conn.dst_ip));
    reverse_parse_port(&(conn.src_port));
    reverse_parse_port(&(conn.dst_port));
    reverse_parse_state(conn.state);
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
Create and destroy the device related functions:
*/

static struct file_operations fops = { 
	.owner = THIS_MODULE,
};

static DEVICE_ATTR(conns, S_IRUGO, display, NULL);

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
