#include <linux/module.h>
#include <linux/kernel.h>
#include rules_functions.h
#include log_clear_functions.h
#include log_show_functions.h
#include hooking_functions.h
#include fw.h


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dana Gur");
MODULE_DESCRIPTION("Stateless firewall");

static int __init my_module_init_function(void) {
	return register_hook() && log_clear_create_dev() && log_show_create_dev() && rules_create_dev();
}

static void __exit my_module_exit_function(void) {
	unregister_hook();
	log_clear_remove_dev();
	log_show_remove_dev();
	rules_remove_dev();
}
module_init(my_module_init_function);
module_exit(my_module_exit_function);

