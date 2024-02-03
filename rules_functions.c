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
static struct class* fw = NULL;
static struct device* rules = NULL;

rule_t *rule_table;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return 0; 
}

static int parse_rule_name(const char *src, char *dst){
	printk(KERN_INFO "in parse_rule_name function\n");
	int size = 0;
	while (src[size]!=' '){
		size++;
	}
	printk(KERN_INFO "size is %d", size);
	strncpy(dst, src, size);
	return size; //return the length of the parsed element 
}

static int parse_direction(const char *src, direction_t *dst){
	printk(KERN_INFO "in parse_direction function\n");
	*dst = src[0]-'0';
	if ((0<=*dst)&&(*dst<=3)){
		return 1; //return the length of the parsed element 
	}
	return -1; //error code
}

static int parse_ack(const char *src, ack_t *dst){
	printk(KERN_INFO "in parse_ack function\n");
	*dst = src[0]-'0';
	if ((0<=*dst)&&(*dst<=3)){
		return 1; //return the length of the parsed element 
	}
	return -1; //error code
}

static int parse_ip(const char *src, __be32 *dst){
	printk(KERN_INFO "in parse_ip function\n");
	int size = 0;
	u8 dst_u8;
	while (src[size]!=' '){
		size++;
	}
	if (in4_pton(src, size, &dst_u8, '.', NULL)==1){
		*dst = (__be32)dst_u8;
		return -1;
	}
	else return size;
}

static int parse_perfix_size(const char *src, __u8 *dst){
	printk(KERN_INFO "in parse_perfix_size function\n");
	unsigned long src_long;
	if (src[1] == ' '){
		char perfix[2];
		perfix[0] = src[1];
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
		perfix[0] = src[1];
		perfix[1] = src[2];
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
	printk(KERN_INFO "in parse_protocol function\n");
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
	printk(KERN_INFO "in parse_action function\n");
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

int check_and_update_idx(int *buf_index, int element_size){
	printk(KERN_INFO "in check_and_update_idx function\n");
	if (element_size==-1){
		return -1; //error code
	}
	*buf_index += element_size+1;
	return 0;
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int rule_table_index = 0;
	int buf_index = 0;
        printk(KERN_INFO "in modify function with %d\n", count);
	buf_index += parse_rule_name(buf+buf_index, rule_table[rule_table_index].rule_name);
	/*while (buf_index<count)
	{
		buf_index += parse_rule_name(buf+buf_index, rule_table[rule_table_index].rule_name);
		if(check_and_update_idx(&buf_index, parse_direction(buf+buf_index, &rule_table[rule_table_index].direction))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &rule_table[rule_table_index].src_ip))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &rule_table[rule_table_index].src_prefix_mask))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_perfix_size(buf+buf_index, &rule_table[rule_table_index].src_prefix_size))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &rule_table[rule_table_index].dst_ip))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &rule_table[rule_table_index].dst_prefix_mask))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_perfix_size(buf+buf_index, &rule_table[rule_table_index].dst_prefix_size))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_protocol(buf+buf_index, &rule_table[rule_table_index].protocol))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ack(buf+buf_index, &rule_table[rule_table_index].ack))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_action(buf+buf_index, &rule_table[rule_table_index].action))==-1){
			return -1;
		}
		rule_table_index++;
	}*/
	return 1;
}

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display, modify);

int rules_create_dev(rule_t *user_rule_table)
{
	printk(KERN_INFO "in rules_create_dev function\n");
	rule_table = user_rule_table;
	//create char device
	major_number = register_chrdev(0, "rules", &fops);\
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	fw = class_create(THIS_MODULE, "fw");
	if (IS_ERR(fw))
	{
		unregister_chrdev(major_number, "rules");
		return -1;
	}
	
	//create sysfs device
	rules = device_create(fw, NULL, MKDEV(major_number, 0), NULL, "rules");	
	if (IS_ERR(rules))
	{
		class_destroy(fw);
		unregister_chrdev(major_number, "rules");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(rules, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		device_destroy(fw, MKDEV(major_number, 0));
		class_destroy(fw);
		unregister_chrdev(major_number, "rules");
		return -1;
	}
	printk(KERN_INFO "Succesful call for create\n");
	return 0;
}

void rules_remove_dev(void)
{
	device_remove_file(rules, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(fw, MKDEV(major_number, 0));
	class_destroy(fw);
	unregister_chrdev(major_number, "rules");
	printk(KERN_INFO "Succesful call for remove\n");
}
