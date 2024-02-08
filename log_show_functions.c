#include "fw.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

char* buffer_index;							// The moving index of the original buffer
static int major_number;					// Major of the char device
static struct class* devices_class = NULL;	// The device's class
static struct device* log_device = NULL;	// The device's name
static char *log_output = NULL;
int position_in_log_output = 0;

static void free_log_output(void){
    if (log_output!=NULL){
        kfree(log_output);
    }
}

static int print_log(log_row_t *log){
    log_output+position_in_log_output = kmalloc(sizeof(log_row_t), GFP_KERNEL);
    if (log_output+position_in_log_output==NULL){
        return -1;
    }
    memcpy(log_output+position_in_log_output, log, sizeof(log_row_t));
    log_to_str(log_output+position_in_log_output, log);
    position_in_log_output+=sizeof(log_row_t);
    return 0;
}

/* Our custom open function  for file_operations --------------------- */
static int my_open(struct inode *_inode, struct file *_file) { 
	return 0;
}

/* Our custom read function  for file_operations --------------------- */
static ssize_t my_read(struct file *filp, char *buff, size_t length, loff_t *offp) {
    free_log_output();
    func_for_log_list(print_log);
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
    free_log_output();
}