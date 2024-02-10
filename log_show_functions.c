#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "fw.h"
#include "manage_log_list.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

int RULE_OUTPUT_SIZE = sizeof(unsigned long)+4+sizeof(__be32)+sizeof(__be16);

char* buffer_index;							// The moving index of the original buffer
static int major_number;					// Major of the char device
static struct class* devices_class = NULL;	// The device's class
static struct device* log_device = NULL;	// The device's name
static char *log_output = NULL;
int position_in_log_output = 0;
int count_log = 0;

static void reverse_parse_timestamp(unsigned long *src){
	char *curr_log_position = log_output+position_in_log_output;
	printk(KERN_INFO "in reverse_parse_timestamp\n");
    memcpy(curr_log_position, src, sizeof(unsigned long));
    position_in_log_output += sizeof(unsigned long);
}

static void reverse_parse_protocol(unsigned char src){
	char *curr_log_position = log_output+position_in_log_output;
	switch (src)
	{
	case 255:
		*curr_log_position = '0';
		break;
	case 1:
		*curr_log_position = '1';
		break;
	case 6:
		*curr_log_position = '2';
		break;
	case 17:
		*curr_log_position = '3';
		break;
	default:
		*curr_log_position = '4';
		break;
	}
	position_in_log_output += 1;
}

static void reverse_parse_action(unsigned char src){
	char *curr_log_position = log_output+position_in_log_output;
	if (src==NF_DROP){
		*curr_log_position='0';
	}
	else
	{
		*curr_log_position='1';
	}
	position_in_log_output += 1;
}

static void reverse_parse_ip(__be32 *src){
	char *curr_log_position = log_output+position_in_log_output;
	memcpy(curr_log_position, src, sizeof(__be32));
	position_in_log_output += sizeof(__be32);
}

static void reverse_parse_port(__be16 *src){
	char *curr_log_position = log_output+position_in_log_output;
	memcpy(curr_log_position, src, sizeof(__be16));
    position_in_log_output += sizeof(__be16);
}

static void reverse_parse_reason(reason_t src){
	char *curr_log_position = log_output+position_in_log_output;
    if (src==REASON_FW_INACTIVE){
        *curr_log_position = 51;
    }
    else if (src==REASON_NO_MATCHING_RULE){
        *curr_log_position = 52;
    }
    else if (src==REASON_XMAS_PACKET){
        *curr_log_position = 53;
    }
    else if (src==REASON_ILLEGAL_VALUE){
        *curr_log_position = 54;
    }
    else {
        *curr_log_position = (char)src;
    }
    position_in_log_output += 1;
}

static void reverse_parse_count(unsigned int *src){
	char *curr_log_position = log_output+position_in_log_output;
	printk(KERN_INFO "in reverse_parse_count\n");
    memcpy(curr_log_position, src, sizeof(unsigned int));
    position_in_log_output += sizeof(unsigned int);
}

static void put_validation_log(char valid_log){
	log_output[position_in_log_output] = valid_log;
	position_in_log_output++;
}

static int print_log(log_row_t log){
printk(KERN_INFO "in print_log\n");
    count_log++;
	put_validation_log(1);
    reverse_parse_timestamp(&(log.timestamp));
    reverse_parse_protocol(log.protocol);
    reverse_parse_action(log.action);
    reverse_parse_ip(&(log.src_ip));
    reverse_parse_ip(&(log.dst_ip));
    reverse_parse_port(&(log.src_port));
    reverse_parse_port(&(log.dst_port));
    reverse_parse_reason(log.reason);
    reverse_parse_count(&(log.count));
	return 0;
}

static ssize_t log_read(struct file *filp, char *buff, size_t length, loff_t *offp) {
int log_list_length = get_log_list_length();
	printk(KERN_INFO "in log read\n");
    count_log = 0;
	log_output = (char*)kmalloc(RULE_OUTPUT_SIZE*log_list_length, GFP_KERNEL);
	if (log_output==NULL){
	printk(KERN_INFO "log output is NULL");
		return -1;
	}
    func_for_log_list(print_log);
	put_validation_log(0);
	if (log_output==NULL){
	printk(KERN_INFO "log output is NULL in 2nd check");
		}
	printk(KERN_INFO "wrote to user: %s\n", log_output);
	printk(KERN_INFO "wrote to user size of %d\n", RULE_OUTPUT_SIZE*log_list_length);
	printk(KERN_INFO "RULE_OUTPUT_SIZE is %d\n", RULE_OUTPUT_SIZE);
    copy_to_user(buff, log_output, RULE_OUTPUT_SIZE*log_list_length);
	kfree(log_output);
	return RULE_OUTPUT_SIZE*log_list_length;
}

static struct file_operations fops = { // Our 'file_operations' struct with declerations on our functions
	.owner = THIS_MODULE,
	.read = log_read,
};

int log_show_create_dev(struct class *devices_class_input) {
    devices_class = devices_class_input;

	major_number = register_chrdev(0, DEVICE_NAME_SHOW_LOG, &fops);\
	if (major_number < 0) {
		return -1;
	}

	log_device = device_create(devices_class, NULL, MKDEV(major_number, MINOR_LOG_SHOW), NULL, DEVICE_NAME_SHOW_LOG);	
	if (IS_ERR(log_device)) {
		class_destroy(devices_class);
		unregister_chrdev(major_number, DEVICE_NAME_SHOW_LOG);
		return -1;
	}	

	return 0;
}

void log_show_remove_dev(void) {
	device_destroy(devices_class, MKDEV(major_number, MINOR_LOG_SHOW));
	class_destroy(devices_class);
	unregister_chrdev(major_number, DEVICE_NAME_SHOW_LOG);
}
