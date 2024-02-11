#include <linux/klist.h>
#include <linux/slab.h> // for kmalloc and kfree
#include "fw.h"

#define POOL_LEN 1

static log_row_t *log_node_pool[POOL_LEN];
static struct klist log_list;
int log_list_length = 0;

void init_log_list(void) {
    printk(KERN_INFO "init of log list");
    klist_init(&log_list, NULL, NULL);
    log_list_length = 0;
}

int add_to_log_list(log_row_t *log) {
    struct klist_node *node;
    if (log == NULL) {
        printk(KERN_INFO "log is NULL in add_to_log_list\n");
        return -1;
    }
    if (log_list_length < POOL_LEN) {
        printk(KERN_INFO "adding to log list in pool in position %d\n", log_list_length);
        log_node_pool[log_list_length] = log;
    } else {
        printk(KERN_INFO "adding to log list in klist\n");
        node = (struct klist_node *)kmalloc(sizeof(struct klist_node), GFP_KERNEL);
        if (!node) {
            return -1;
        }
        klist_add_tail(node, &log_list);
        node->n_klist = log;
    }
    log_list_length++;
    printk(KERN_INFO "assigned log_list_length=%d\n", log_list_length);
    if (node->n_klist == NULL) {
        printk(KERN_INFO "node->n_klist is NULL in add_to_log_list\n");
    }
    return 0;
}

void remove_all_from_log_list(void) {
    struct klist_node *node, *tmp;
    int i;
    for (i=0; (i<log_list_length)&&(i<POOL_LEN);i++){
        free(log_node_pool[i]);
    }
    klist_for_each_entry_safe(node, tmp, &log_list, n_klist) {
        free(node->n_klist); //free the log itself
        klist_del(node);
        kfree(node);
    }
    log_list_length = 0;
}

int get_log_list_length(void) {
    return log_list_length;
}

log_row_t *find_identical_log(log_row_t *log, int (*compare_logs)(log_row_t *, log_row_t *)) {
    struct klist_node *node;
    int i;
    for (i=0; (i<log_list_length)&&(i<POOL_LEN);i++){
        if (compare_logs(log_node_pool[i], log)) {
            return log_node_pool[i];
        }
    }
    klist_for_each_entry(node, &log_list, n_klist) {
        if (compare_logs(node->n_klist, log)) {
            return node->n_klist;
        }
    }
    return NULL;
}

int func_for_log_list(int (*func)(log_row_t)) {
    struct klist_node *node;
    int func_result;
    int i;
    for (i=0; (i<log_list_length)&&(i<POOL_LEN);i++){
        func_result = func(*(log_node_pool[i]));
        if (func_result != 0) {
            return -1;
        }
    }
    klist_for_each_entry(node, &log_list, n_klist) {
        func_result = func(*((log_row_t *)(node->n_klist)));
        if (func_result != 0) {
            return -1;
        }
    }
    return 0;
}
