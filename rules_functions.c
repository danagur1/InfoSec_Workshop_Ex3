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

const int RULE_FILEDS = 13;

typedef int (*ParseFieldFuncPointer)(rule_t*);

static int major_number;
static struct class* fw_class = NULL;
static struct device* rules = NULL;

static rule_t *rule_table;
static int *rule_table_size;

const char *input_buf_pointer;
int input_buf_index;

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

static int parse_rule_name(rule_t *curr_rule){
	char *dst = curr_rule->rule_name;
	if ((input_buf_pointer+input_buf_index)[20]!='\0'){
		return -1; //error code
	}
    memcpy(dst, input_buf_pointer+input_buf_index, 21*sizeof(char));
	return 21*sizeof(char); //return the length of the parsed element 
}

static int parse_direction(rule_t *curr_rule){
	direction_t *dst = &(curr_rule->direction);
	*dst = (input_buf_pointer+input_buf_index)[0];
	if ((0<=*dst)&&(*dst<=3)){
		return 1; //return the length of the parsed element 
	}
	return -1; //error code
}

static int parse_ip(__be32 *dst){
	memcpy(dst, input_buf_pointer+input_buf_index, sizeof(__be32));
	return sizeof(__be32); //return the length of the parsed element
}

static int parse_src_ip(rule_t *curr_rule){
	return parse_ip(&(curr_rule->src_ip));
}

static int parse_src_prefix_mask(rule_t *curr_rule){
	return parse_ip(&(curr_rule->src_prefix_mask));
}

static int parse_dst_ip(rule_t *curr_rule){
	return parse_ip(&(curr_rule->dst_ip));
}

static int parse_dst_prefix_mask(rule_t *curr_rule){
	return parse_ip(&(curr_rule->dst_prefix_mask));
}

static int parse_prefix_size(__u8 *dst){
	memcpy(dst, input_buf_pointer+input_buf_index, sizeof(__u8));
	return sizeof(__u8); //return the length of the parsed element
}

static int parse_src_prefix_size(rule_t *curr_rule){
	return parse_prefix_size(&(curr_rule->src_prefix_size));
}

static int parse_dst_prefix_size(rule_t *curr_rule){
	return parse_prefix_size(&(curr_rule->dst_prefix_size));
}

static int parse_protocol(rule_t *curr_rule){
	__u8 *dst = &(curr_rule->protocol);
	switch ((input_buf_pointer+input_buf_index)[0])
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
		return -1; //error code
	}	
	return 1; //return the length of the parsed element
}

static int parse_port(__be16 *dst){
	memcpy(dst, (input_buf_pointer+input_buf_index), sizeof(__le16));
	return sizeof(__le16); //return the length of the parsed element
}

static int parse_src_port(rule_t *curr_rule){
	return parse_port(&(curr_rule->src_port));
}

static int parse_dst_port(rule_t *curr_rule){
	return parse_port(&(curr_rule->dst_port));
}

static int parse_ack(rule_t *curr_rule){
	ack_t *dst = &(curr_rule->ack);
	*dst = (input_buf_pointer+input_buf_index)[0]-'0';
	if ((0<=*dst)&&(*dst<=3)){
		return 1; //return the length of the parsed element 
	}
	return -1; //error code
}

static int parse_action(rule_t *curr_rule){
	__u8 *dst = &(curr_rule->action);
	if ((input_buf_pointer+input_buf_index)[0]=='0'){
		*dst=NF_DROP;
	}
	else if ((input_buf_pointer+input_buf_index)[0]=='1')
	{
		*dst=NF_ACCEPT;
	}
	else{
		return -1; //error code
	}
	return 1; //return the length of the parsed element
	
}

//parse the whole rule- call every other parsing function on the rule
int parse_rule(ParseFieldFuncPointer funcs[], rule_t *curr_rule){
	int element_size;
	int func_idx;
	for (func_idx=0; func_idx< RULE_FILEDS; func_idx++){
		element_size = funcs[func_idx](curr_rule);
		if (element_size==-1){
			return -1;
		}
		else{
			input_buf_index += element_size+1;
		}
	}
	return 0;
}


//sysfs store implementation- parse all the rule componenets from driver
ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int rule_table_index = 0;
	input_buf_index = 0;
	input_buf_pointer = buf;
	while (input_buf_index<count)
	{
		rule_t *curr_rule = rule_table+rule_table_index;
		ParseFieldFuncPointer parse_funcs[] = {parse_rule_name, parse_direction, parse_src_ip, parse_src_prefix_mask, \
		parse_src_prefix_size, parse_dst_ip, parse_dst_prefix_mask, parse_dst_prefix_size, parse_protocol, parse_src_port, \
		parse_dst_port, parse_ack, parse_action};
		parse_rule(parse_funcs, curr_rule);
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
