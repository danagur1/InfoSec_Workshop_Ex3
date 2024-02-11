#include <linux/klist.h>
#include <linux/slab.h> // for kmalloc and kfree
#include "fw.h"

static int POOL_LEN = 1;
static struct klist_node log_node_pool[POOL_LEN];
static struct klist log_list;
int log_list_length = 0;

void init_log_list(void){
printk(KERN_INFO "init of log list");
    klist_init(&log_list, NULL, NULL);
    log_list_length = 0;
}

int add_to_log_list(log_row_t *log) {
    struct klist_node *node;
    if (log==NULL){
        printk(KERN_INFO "log is NULL in add_to_log_list\n");
    }
printk(KERN_INFO "in add to list. time passed is %lu\n", log->timestamp);
    printk(KERN_INFO "log_list_length=%d\n", log_list_length);
    if (log_list_length<POOL_LEN){
        printk(KERN_INFO "adding to log list in pool in position %d\n", log_list_length);
        node = &log_node_pool[log_list_length++]; 
    }
    else{
        printk(KERN_INFO "adding to log list in klist\n");
        node = (struct klist_node*)kmalloc(sizeof(struct klist_node), GFP_KERNEL);
        if (!node) {
	        return -1;
        }
        klist_add_tail(node, &log_list);
    }
    node->n_klist = log;
    printk(KERN_INFO "assigned log_list_length=%d\n", log_list_length);
    if (node->n_klist==NULL){
        printk(KERN_INFO "node->n_klist is NULL in add_to_log_list\n");
    }
printk(KERN_INFO "in add to list#2. time passed is %lu\n", ((log_row_t*)(log_node_pool[0].n_klist))->timestamp);
printk(KERN_INFO "in add to list#3. time passed is %lu\n", ((log_row_t*)(node->n_klist))->timestamp);
    return 0;
}

int get_log_list_length(void){
if (log_list_length>0){
printk(KERN_INFO "in get_log_list_length #1. time passed is %lu\n", ((log_row_t*)(log_node_pool[0].n_klist))->timestamp);
}
    return log_list_length;
}

void remove_all_from_log_list(void) {
    struct klist_iter iter;
    struct klist_node *node;
    int i;
    int array_length = log_list_length;
    if (array_length>POOL_LEN){
        array_length = POOL_LEN;
    }
    for (i = 0; i < array_length; i++) {
        kfree(log_node_pool[i].n_klist); //free the log itsself also 
    }
    printk(KERN_INFO "clearing log list");
    if (log_list_length>POOL_LEN){
        klist_iter_init(&log_list, &iter);
        while ((node = klist_next(&iter)) != NULL) {
            kfree(node->n_klist); //free the log itsself also 
            klist_del(node);
            kfree(node);
        } 
        klist_iter_exit(&iter);
    }
    log_list_length=0;
}

log_row_t *find_identical_log(log_row_t *log, int (*compare_logs)(log_row_t*, log_row_t*)) {
    struct klist_iter iter;
    struct klist_node *node;
    int array_length = log_list_length;
    int i;
if (array_length>0){
printk(KERN_INFO "in find_identical_log #1. time passed is %lu\n", ((log_row_t*)(log_node_pool[0].n_klist))->timestamp);
}
    if (array_length>POOL_LEN){
        array_length = POOL_LEN;
    }
    for (i = 0; i < array_length; i++) {
        if (compare_logs(log_node_pool[i].n_klist, log)) {
            return log_node_pool[i].n_klist;
        }
    }
    klist_iter_init(&log_list, &iter);
    while ((node = klist_next(&iter)) != NULL) {
        if (compare_logs(node->n_klist, log)) {
            klist_iter_exit(&iter);
            return node->n_klist;
        }
    }
    klist_iter_exit(&iter);
if (array_length>0){
printk(KERN_INFO "in find_identical_log #2. time passed is %lu\n", ((log_row_t*)(log_node_pool[0].n_klist))->timestamp);
}
    return NULL;
}

int func_for_log_list(int (*func)(log_row_t)) {
    struct klist_iter iter;
    struct klist_node *node;
    int func_result;
    int array_length = log_list_length;
    int i;
    if (array_length>POOL_LEN){
        array_length = POOL_LEN;
    }
    for (i = 0; i < array_length; ++i) {
printk(KERN_INFO "in loop over pull with i=%d, array_length=%d\n", i, array_length);
if ((log_row_t*)(log_node_pool[i].n_klist)==NULL){
printk(KERN_INFO "(log_row_t*)(log_node_pool[i].n_klist) is NULL in func_for_log_list\n");
}
        func_result = func(*((log_row_t*)(log_node_pool[i].n_klist)));
        if (func_result != 0) {
            return -1;
        }
    }
printk(KERN_INFO "Before loop over klist and after loop over log_node_pool\n");
    klist_iter_init(&log_list, &iter);
    while ((node = klist_next(&iter)) != NULL) {
        func_result = func(*((log_row_t*)(node->n_klist)));
        if (func_result!=0){
            return -1;
        }
    }
    klist_iter_exit(&iter);
    return 0;
}


