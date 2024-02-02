#include devices_fucntions.h
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "fw.h"

static int major_number;
static struct class* fw = NULL;
static struct device* rules = NULL;

static unsigned int sysfs_int = 0;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", sysfs_int);
}

ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		sysfs_int = temp;
	return count;	
}

static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display, modify);

int rules_create_dev(void)
{
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
	rules = device_create(fw, NULL, MKDEV(major_number, 0), NULL, "fw" "_" "rules");	
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
	
	return 0;
}

void rules_remove_dev(void)
{
	device_remove_file(rules, (const struct device_attribute *)&dev_attr_rules.attr);
	device_destroy(fw, MKDEV(major_number, 0));
	class_destroy(fw);
	unregister_chrdev(major_number, "rules");
}

module_init(sysfs_example_init);
module_exit(sysfs_example_exit);
