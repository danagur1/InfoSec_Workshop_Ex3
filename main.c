#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include "rules_functions.h"
#include "hooking_functions.h"
//#include "log_clear_functions.h"
#include "log_show_functions.h"
//#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

static rule_t *first_rule_table;

static int __init my_module_init_function(void) {
	int first_rule_table_size=0;
	struct class *devices_class;
	first_rule_table= (rule_t*)kmalloc(sizeof(rule_t)*MAX_RULES, GFP_KERNEL);
	devices_class = rules_create_dev(first_rule_table, &first_rule_table_size);
	if (devices_class==NULL){
		return -1;
	}
	if (log_show_create_dev(devices_class)<0){
		return -1;
	}
	if (register_hook(first_rule_table, &first_rule_table_size)<0){
		return -1;
	}
	return 0; //all the functions 
}

static void __exit my_module_exit_function(void) {
	kfree(first_rule_table);
	rules_remove_dev();
	unregister_hook();
	log_show_remove_dev();
	/*
	unregister_hook();
	log_clear_remove_dev();
	log_show_remove_dev();*/
	//rules_remove_dev();
	return;
}
module_init(my_module_init_function);
module_exit(my_module_exit_function);
