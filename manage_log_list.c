#include <linux/klist.h>
#include <linux/slab.h> // for kmalloc and kfree
#include "fw.h"

struct log_list_node {
    log_row_t *log;
    struct klist_node node;
};

static struct klist log_list;

// Define callback functions
static void log_klist_release(struct klist_node *n) {
    struct log_list_node *entry = container_of(n, struct log_list_node, node);
    kfree(entry);
}

static void log_klist_get(struct klist_node *n) {
    // No special handling required in this example
}

static struct klist_node_ops log_klist_ops = {
    .release = log_klist_release,
    .get = log_klist_get,
};

void init_log_list(void) {
    klist_init(&log_list, &log_klist_ops);
}
/*
void init_log_list(void) {
    klist_init(&log_list);
}*/

int add_to_log_list(log_row_t *log) {
    struct log_list_node *new_node = kmalloc(sizeof(struct log_list_node), GFP_KERNEL);
    if (!new_node)
        return -1;
    new_node->log = log;
    klist_add_tail(&new_node->node, &log_list.k_head);
    return 0;
}

void remove_all_from_log_list(void) {
    struct log_list_node *entry;
    struct klist_node *kn;
    klist_iter_init_node(&log_list, &kn);
    while ((entry = container_of(kn, struct log_list_node, node))) {
        klist_iter_exit(&log_list, kn);
        klist_del(&entry->node);
        kfree(entry);
        klist_iter_init_node(&log_list, &kn);
    }
}

int func_for_log_list(int (*func)(log_row_t)) {
    struct my_list_node *entry;
    struct klist_node *pos;
    int result;
    klist_for_each_entry(entry, &log_list, node) {
        result= func(*(entry->log));
        if (result==-1){
            return -1;
        }
    }
    return 0;
}

log_row_t *find_identical_log(log_row_t *log, int (*compare_logs)(log_row_t *log1, log_row_t *log2)) {
    struct log_list_node *entry;
    struct klist_node *pos;
    klist_for_each_entry(entry, &log_list, node) {
        if (compare_logs(entry->log, log)) {
            return entry->log; 
        }
    }
    return NULL; 
}
