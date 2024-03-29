#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "fw.h"
#include "manage_log_list.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

static int major_number;
static struct class* fw_class = NULL;
static struct device* sysfs_device = NULL;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

static ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	remove_all_from_log_list();
	return 1;		
}

static DEVICE_ATTR(reset, S_IWUSR | S_IRUGO , NULL, modify);

int log_clear_create_dev(struct class *devices_class)
{
	fw_class = devices_class;
	//create char device
	major_number = register_chrdev(0, DEVICE_NAME_CLEAR_LOG, &fops);\
	if (major_number < 0)
		return -1;
		
	
	//create sysfs device
	sysfs_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_LOG_CLEAR), NULL, DEVICE_NAME_CLEAR_LOG);	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME_CLEAR_LOG);
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG_CLEAR));
		class_destroy(fw_class);
		unregister_chrdev(major_number, DEVICE_NAME_CLEAR_LOG);
		return -1;
	}
	
	return 0;
}

void log_clear_remove_dev(void)
{
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_reset.attr);
	device_destroy(fw_class, MKDEV(major_number, MINOR_LOG_CLEAR));
	unregister_chrdev(major_number, DEVICE_NAME_CLEAR_LOG);
}
