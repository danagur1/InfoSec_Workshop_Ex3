#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/inet.h>

#include "fw.h"
#include "rules_functions.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

static int major_number;
static struct class* fw_class = NULL;
static struct device* rules = NULL;

static rule_t *rule_table;
static int *rule_table_size;

static char *not_parsed_input = NULL;

static struct file_operations fops = {
	.owner = THIS_MODULE
};


/*
Display related functions: store the input without parsing and parse it in user-mode program
*/

static void free_input_buf(void){
	if (not_parsed_input!=NULL){
		kfree(not_parsed_input);
	}
}

static int store_not_parsed_input(const char *buf, size_t count){
	free_input_buf();
	not_parsed_input = (char*)kmalloc(count*sizeof(char), GFP_KERNEL);
	if (not_parsed_input==NULL){
		return -1;
	}
	strncpy(not_parsed_input, buf, count);
	return 0;
}

static ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return sprintf(buf, "%s\n", not_parsed_input);
}


/*
Parse rule values from written to the driver:
*/

static int parse_rule_name(const char *src, char *dst){
	int size = 0;
	while (src[size]!=' '){
		size++;
		if (size>20){
			return -1;
		}
	}
	strncpy(dst, src, size);
	dst[size] = '\0';
	return size; //return the length of the parsed element 
}

static int parse_direction(const char *src, direction_t *dst){
	*dst = src[0]-'0';
	if ((0<=*dst)&&(*dst<=3)){
		return 1; //return the length of the parsed element 
	}
	return -1; //error code
}

static int parse_ack(const char *src, ack_t *dst){
	*dst = src[0]-'0';
	if ((0<=*dst)&&(*dst<=3)){
		return 1; //return the length of the parsed element 
	}
	return -1; //error code
}

static int parse_ip(const char *src, __be32 *dst){
	int size = 0;
	struct in_addr addr;
	while (src[size]!=' '){
		size++;
	}
	if (in4_pton(src, size, (u8 *)&addr, -1, NULL)!=1){
		return -1;
	}
	*dst = addr.s_addr;
	return size;
}

static int parse_perfix_size(const char *src, __u8 *dst){
	unsigned long src_long;
	if (src[1] == ' '){
		char perfix[2];
		perfix[0] = src[0];
		perfix[1] ='\0';
		if (kstrtoul(perfix, 10, &src_long)!=0){
			return -1;
		}
		*dst = (__u8)src_long;
		return 1;
	}
	else if (src[2] == ' ')
	{
		char perfix[3];
		perfix[0] = src[0];
		perfix[1] = src[1];
		perfix[2] ='\0';
		if (kstrtoul(perfix, 10, &src_long)!=0){
			return -1;
		}
		*dst = (__u8)src_long;
		return 2;
	}
	else{
		return -1;
	}
}

static int parse_protocol(const char *src, __u8 *dst){
	switch (src[0])
	{
	case '0':
		*dst = 255;
		break;
	case '1':
		*dst = 1;
		break;
	case '2':
		*dst = 6;
		break;
	case '3':
		*dst = 17;
		break;
	case '4':
		*dst = 143;
		break;
	default:
		return -1;
	}	
	return 1;
}

static int parse_action(const char *src, __u8 *dst){
	if (src[0]=='0'){
		*dst=NF_DROP;
	}
	else if (src[0]=='1')
	{
		*dst=NF_ACCEPT;
	}
	else{
		return -1;
	}
	return 1;
	
}

static int parse_port(const char *src, __be16 *dst){
	unsigned long src_int;
	int size = 0;
	char *short_src;
	while (src[size]!=' '){
		size++;
	}
	short_src = (char*)kmalloc(size*sizeof(char), GFP_KERNEL);
	if (!short_src){
		return -1;
	}
	strncpy(short_src, src, size);
	short_src[size]='\0';
	if ((kstrtoul(short_src, 10, &src_int) != 0)||((src_int<0)||(src_int>1023))){
		kfree(short_src);
		return -1;
	}
	kfree(short_src);
	*dst = htons((__be16)src_int);
	return size;
}


//Update the current index in buf by the size of element read
int check_and_update_idx(int *buf_index, int element_size){
	if (element_size==-1){
		return -1; //error code
	}
	*buf_index += element_size+1;
	return 0;
}


//sysfs store implementation- parse all the rule componenets from driver
ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int rule_table_index = 0;
	int buf_index = 0;
	while (buf_index<count)
	{
		rule_t *curr_rule = rule_table+rule_table_index;
		buf_index += parse_rule_name(buf+buf_index, 
		rule_table[rule_table_index].rule_name)+1;
		if(check_and_update_idx(&buf_index, parse_direction(
		buf+buf_index, &curr_rule->direction))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &curr_rule->src_ip))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &curr_rule->src_prefix_mask))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_perfix_size(buf+buf_index, &curr_rule->src_prefix_size))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &curr_rule->dst_ip))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &curr_rule->dst_prefix_mask))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_perfix_size(buf+buf_index, &curr_rule->dst_prefix_size))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_protocol(buf+buf_index, &curr_rule->protocol))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_port(buf+buf_index, &curr_rule->src_port))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_port(buf+buf_index, &curr_rule->dst_port))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ack(buf+buf_index, &curr_rule->ack))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_action(buf+buf_index, &curr_rule->action))==-1){
			return -1;
		}
		rule_table_index++;
	}
	*rule_table_size = rule_table_index;
	if (store_not_parsed_input(buf, count)==-1){
		return -1;
	}
	return count;
}


/*
Create and destroy the device related functions:
*/

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display, modify);

struct class *rules_create_dev(rule_t *user_rule_table, int *user_rule_table_size)
{
	rule_table = user_rule_table;
	rule_table_size = user_rule_table_size;

	//create char device
	major_number = register_chrdev(0, DEVICE_NAME_RULES, &fops);\
	if (major_number < 0)
		return NULL;
		
	//create sysfs class
	fw_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(fw_class))
	{
		unregister_chrdev(major_number, DEVICE_NAME_RULES);
		return NULL;
	}
	
	//create sysfs device
	rules = device_create(fw_class, NULL, MKDEV(major_number, MINOR_RULES), NULL, DEVICE_NAME_RULES);	
	if (IS_ERR(rules))
	{
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME_RULES);
		return NULL;
	}
	
	//create sysfs file attributes	
	if (device_create_file(rules, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME_RULES);
		return NULL;
	}
	return fw_class;
}

void rules_remove_dev(void)
{
	device_remove_file(rules, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(fw_class, MKDEV(major_number, MINOR_RULES));
	unregister_chrdev(major_number, DEVICE_NAME_RULES);
	free_input_buf();
}
