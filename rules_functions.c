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

static rule_t *rule_table;
<<<<<<< HEAD
static int *rule_table_size=0;
=======
static int *rule_table_size;
>>>>>>> a736b98f3a2ba172ad3e23855f12f070b2edb991

static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return 0; 
}

static int parse_rule_name(const char *src, char *dst){
	int size = 0;
	//printk(KERN_INFO "in parse_rule_name function\n");
	while (src[size]!=' '){
		size++;
		if (size>20){
			return -1;
		}
	}
	strncpy(dst, src, size);
	dst[size] = '\0';
	//printk(KERN_INFO "name is: %s, size is %d\n", dst, size);
	return size; //return the length of the parsed element 
}

static int parse_direction(const char *src, direction_t *dst){
	//printk(KERN_INFO "in parse_direction function\n");
	*dst = src[0]-'0';
	//printk(KERN_INFO "src[0] is: %d and also %c, '0' is %d, *dst is %d\n", src[0], src[0], '0',*dst);
	if ((0<=*dst)&&(*dst<=3)){
		return 1; //return the length of the parsed element 
	}
	return -1; //error code
}

static int parse_ack(const char *src, ack_t *dst){
	//printk(KERN_INFO "in parse_ack function\n");
	*dst = src[0]-'0';
	if ((0<=*dst)&&(*dst<=3)){
		return 1; //return the length of the parsed element 
	}
	return -1; //error code
}

static int parse_ip(const char *src, __be32 *dst){
	int size = 0;
	//printk(KERN_INFO "in parse_ip function\n");
	while (src[size]!=' '){
		size++;
	}
<<<<<<< HEAD
	if (in4_pton(src, size, (u8 *)dst, -1, NULL)!=1){
	//printk(KERN_INFO "could not convert. src= %.9s\n", src);
=======
	struct in_addr addr;
	if (in4_pton(src, size, (u8 *)&addr, -1, NULL)!=1){
>>>>>>> a736b98f3a2ba172ad3e23855f12f070b2edb991
		return -1;
	}
	*dst = addr.s_addr;
	printk(KERN_INFO "converted ip. src= %.9s\n, *dst=%u", src, *dst);
	return size;
}

static int parse_perfix_size(const char *src, __u8 *dst){
	unsigned long src_long;
	//printk(KERN_INFO "in parse_perfix_size function\n");
	if (src[1] == ' '){
		char perfix[2];
		perfix[0] = src[0];
		perfix[1] ='\0';
		if (kstrtoul(perfix, 10, &src_long)!=0){
			return -1;
		}
		*dst = (__u8)src_long;
		//printk(KERN_INFO "parse_perfix_size is %d\n", *dst);
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
		//printk(KERN_INFO "parse_perfix_size is %d\n", *dst);
		return 2;
	}
	else{
		return -1;
	}
}

static int parse_protocol(const char *src, __u8 *dst){
	//printk(KERN_INFO "in parse_protocol function\n");
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
	//printk(KERN_INFO "in parse_action function\n");
	if (src[0]=='0'){
		*dst=NF_DROP;
	}
	else if (src[0]=='1')
	{
		*dst=NF_ACCEPT;
	}
	else{
		//printk(KERN_INFO "failed to parse action because src[0]=%c\n", src[0]);
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
	//printk(KERN_INFO "after copy. size: %d,short_src: %s\n", size, short_src);
	if ((kstrtoul(short_src, 10, &src_int) != 0)||((src_int<0)||(src_int>1023))){
		kfree(short_src);
		return -1;
	}
	kfree(short_src);
	*dst = htons((__be16)src_int);
	return size;
}

int check_and_update_idx(int *buf_index, int element_size){
	//printk(KERN_INFO "in check_and_update_idx function\n");
	if (element_size==-1){
	//printk(KERN_INFO "element_size: %d\n", element_size);
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
	while (buf_index<count)
	{
	//printk(KERN_INFO "continue because buf_index=%d\n, count=%d\n", buf_index, count);
		buf_index += parse_rule_name(buf+buf_index, rule_table[rule_table_index].rule_name)+1;
		if(check_and_update_idx(&buf_index, parse_direction(buf+buf_index, &rule_table[rule_table_index].direction))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &rule_table[rule_table_index].src_ip))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &rule_table[rule_table_index].src_prefix_mask))==-1){
			return -1;
		}
//printk(KERN_INFO "before src_prefix_size and now buf_index=%d and has-%.10s near it and before it-%.3s\n", buf_index, buf+buf_index, buf+buf_index-3);
		if(check_and_update_idx(&buf_index, parse_perfix_size(buf+buf_index, &rule_table[rule_table_index].src_prefix_size))==-1){
			return -1;
		}
//printk(KERN_INFO "before dst_ip and now buf_index=%d and has-%.10s near it and before it-%.3s\n", buf_index, buf+buf_index, buf+buf_index-3);
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &rule_table[rule_table_index].dst_ip))==-1){
			return -1;
		}
		//printk(KERN_INFO "before dst_prefix_mask and now buf_index=%d and has-%.10s near it and before it-%.3s\n", buf_index, buf+buf_index, buf+buf_index-3);
		if(check_and_update_idx(&buf_index, parse_ip(buf+buf_index, &rule_table[rule_table_index].dst_prefix_mask))==-1){
			return -1;
		}
		//printk(KERN_INFO "before dst prefix_size and now buf_index=%d and has-%.10s near it and before it-%.3s\n", buf_index, buf+buf_index, buf+buf_index-3);
		if(check_and_update_idx(&buf_index, parse_perfix_size(buf+buf_index, &rule_table[rule_table_index].dst_prefix_size))==-1){
			return -1;
		}
//printk(KERN_INFO "after dst prefix_size and now buf_index=%d and has-%.10s near it and before it-%.3s\n", buf_index, buf+buf_index, buf+buf_index-3);
		if(check_and_update_idx(&buf_index, parse_protocol(buf+buf_index, &rule_table[rule_table_index].protocol))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_port(buf+buf_index, &rule_table[rule_table_index].src_port))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_port(buf+buf_index, &rule_table[rule_table_index].dst_port))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_ack(buf+buf_index, &rule_table[rule_table_index].ack))==-1){
			return -1;
		}
		if(check_and_update_idx(&buf_index, parse_action(buf+buf_index, &rule_table[rule_table_index].action))==-1){
			return -1;
		}
		buf_index--;
		//printk(KERN_INFO "ended the loop and not buf_index=%d and has %.10s near it and before it %.3s\n", buf_index, buf+buf_index, buf+buf_index-3);
		rule_table_index++;
	}
<<<<<<< HEAD
	printk(KERN_INFO "ended rules_functions")
	*rule_table_size = rule_table_index;
=======
	printk(KERN_INFO "*finished loop");
	*rule_table_size = rule_table_index;
	printk(KERN_INFO "*rule_table_size=%d\n", *rule_table_size);
>>>>>>> a736b98f3a2ba172ad3e23855f12f070b2edb991
	return count;
}

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display, modify);

int rules_create_dev(rule_t *user_rule_table, int *user_rule_table_size)
{
	//printk(KERN_INFO "in rules_create_dev function\n");
	rule_table = user_rule_table;
	rule_table_size = user_rule_table_size;
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
	//printk(KERN_INFO "Succesful call for create\n");
	return 0;
}

void rules_remove_dev(void)
{
	device_remove_file(rules, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(fw, MKDEV(major_number, 0));
	class_destroy(fw);
	unregister_chrdev(major_number, "rules");
	//printk(KERN_INFO "Succesful call for remove\n");
}
