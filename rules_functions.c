#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "fw.h"
#include "rules_functions.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

int rules_create_dev(void)
{
	printk(KERN_INFO "Succesful call for create\n");
	return 0;
}

void rules_remove_dev(void)
{
	printk(KERN_INFO "Succesful call for remove\n");
}
