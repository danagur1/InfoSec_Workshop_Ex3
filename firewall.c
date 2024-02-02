#include <linux/module.h>
#include <linux/kernel.h>

static int __init my_module_init_function(void) {
	return 0; /* if non-0 return means init_module failed */
}

static void __exit my_module_exit_function(void) {
	return;
}
module_init(my_module_init_function);
module_exit(my_module_exit_function);

