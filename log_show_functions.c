#include "fw.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");


static int str_len;							// Length of 'test_String'
char* buffer_index;							// The moving index of the original buffer
static int major_number;					// Major of the char device
static struct class* devices_class = NULL;	// The device's class
static struct device* log_device = NULL;	// The device's name


/* Our custom open function  for file_operations --------------------- */
static int my_open(struct inode *_inode, struct file *_file) { // Each time we open the device we initilize the changing variables ( so we will be able to read it again and again
	return 0;
}

/* Our custom read function  for file_operations --------------------- */
static ssize_t my_read(struct file *filp, char *buff, size_t length, loff_t *offp) {
	return 0;
}

static struct file_operations fops = { // Our 'file_operations' struct with declerations on our functions
	.owner = THIS_MODULE,
	.read = my_read,
	.open = my_open
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