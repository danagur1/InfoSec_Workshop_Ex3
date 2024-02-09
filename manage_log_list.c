#include <linux/klist.h>
#include <linux/slab.h> // for kmalloc and kfree
#include "fw.h"

static struct klist log_list;

void init_log_list(void){
printk(KERN_INFO "init of log list");
    klist_init(&log_list, NULL, NULL);
}

int add_to_log_list(log_row_t *log) {
    struct klist_node *node = kmalloc(sizeof(struct klist_node), GFP_KERNEL);
printk(KERN_INFO "adding to log list");
    if (!node) {
	return -1;
    }
    printk(KERN_INFO "Allocated memory\n");
    klist_add_tail(node, &log_list);
    node->n_klist = log;
    return 0;
}

void remove_all_from_log_list(void) {
    struct klist_iter iter;
    struct klist_node *node;
printk(KERN_INFO "clearing log list");
    klist_iter_init(&log_list, &iter);
    while ((node = klist_next(&iter)) != NULL) {
        klist_del(node);
        kfree(node);
    } 
    klist_iter_exit(&iter);
}

log_row_t *find_identical_log(log_row_t *log, int (*compare_logs)(log_row_t*, log_row_t*)) {
    struct klist_iter iter;
    struct klist_node *node;
printk(KERN_INFO "searching in log list");
    klist_iter_init(&log_list, &iter);
    while ((node = klist_next(&iter)) != NULL) {
        if (compare_logs(node->n_klist, log) == 0) {
            klist_iter_exit(&iter);
            return node->n_klist;
        }
    }
    klist_iter_exit(&iter);
    return NULL;
}

int func_for_log_list(int (*func)(log_row_t)) {
    struct klist_iter iter;
    struct klist_node *node;
    int func_result;
printk(KERN_INFO "making functions on log list");
    klist_iter_init(&log_list, &iter);
    while ((node = klist_next(&iter)) != NULL) {
        func_result = func(*((log_row_t*)(node->n_klist)));\
        if (func_result!=0){
            return -1;
        }
    }
    klist_iter_exit(&iter);
    return 0;
}


