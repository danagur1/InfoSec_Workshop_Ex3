#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

static int major_number;
static struct class* fw_class = NULL;
static struct device* sysfs_device = NULL;

static unsigned int sysfs_int = 0;

static struct file_operations fops = {
	.owner = THIS_MODULE
};

static ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u\n", sysfs_int);
}

static ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	int temp;
	if (sscanf(buf, "%u", &temp) == 1)
		sysfs_int = temp;
	return count;	
}

static DEVICE_ATTR(sysfs_att, S_IWUSR | S_IRUGO , display, modify);

int log_clear_create_dev(struct class *devices_class)
{
	fw_class = devices_class;
	//create char device
	major_number = register_chrdev(0, "log", &fops);\
	if (major_number < 0)
		return -1;
		
	
	//create sysfs device
	sysfs_device = device_create(fw_class, NULL, MKDEV(major_number, MINOR_LOG), NULL, "log");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(fw_class);
		unregister_chrdev(major_number, "log");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr))
	{
		device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
		class_destroy(fw_class);
		unregister_chrdev(major_number, "log");
		return -1;
	}
	
	return 0;
}

void log_clear_remove_dev(void)
{
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_sysfs_att.attr);
	device_destroy(fw_class, MKDEV(major_number, MINOR_LOG));
	class_destroy(fw_class);
	unregister_chrdev(major_number, "log");
}
