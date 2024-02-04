#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include "rules_functions.h"
#include "hooking_functions.h"
//#include "log_clear_functions.h"
//#include "log_show_functions.h"
//#include "fw.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

rule_t *my_rule_table;

static int __init my_module_init_function(void) {
	my_rule_table= (rule_t*)kmalloc(sizeof(rule_t)*MAX_RULES, GFP_KERNEL);
	printk(KERN_INFO "Succesful call for init\n");
	//struct klist log_list;
	return rules_create_dev(my_rule_table);
	//return rules_create_dev(rule_table);/*register_hook() && log_clear_create_dev() && log_show_create_dev() && rules_create_dev();*/
}

static void __exit my_module_exit_function(void) {
	kfree(my_rule_table);
	rules_remove_dev();
	/*
	unregister_hook();
	log_clear_remove_dev();
	log_show_remove_dev();*/
	//rules_remove_dev();
	return;
}
module_init(my_module_init_function);
module_exit(my_module_exit_function);
