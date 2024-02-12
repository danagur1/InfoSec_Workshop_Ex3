#include <linux/klist.h>
#include <linux/slab.h> // for kmalloc and kfree
#include "fw.h"

struct log_in_list {
    log_row_t *data;
    struct list_head log_list_element;
};

static LIST_HEAD(log_list);
int log_list_length = 0;

void init_log_list(void) {
    INIT_LIST_HEAD(&log_list);
}

int add_to_log_list(log_row_t *log) {
    struct log_in_list *entry;
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    entry->data = log;
    INIT_LIST_HEAD(&entry->log_list_element);
    list_add_tail(&entry->log_list_element, &log_list);
    return 0;
}

void remove_all_from_log_list(void) {
    struct log_in_list *entry, *next;
    list_for_each_entry_safe(entry, next, &log_list, log_list_element) {
        list_del(&entry->log_list_element);
        kfree(entry->data);
        kfree(entry);
    }
    log_list_length = 0;
}

int get_log_list_length(void) {
    return log_list_length;
}

log_row_t *find_identical_log(log_row_t *log, int (*compare_logs)(log_row_t *, log_row_t *)) {
    struct log_in_list *entry;
    struct log_in_list *tmp;
    list_for_each_entry_safe(entry, tmp, &log_list, log_list_element) {
        if(compare_logs(entry->data, log)){
            return entry->data;
        }
    }
    return NULL;
}

int func_for_log_list(int (*func)(log_row_t)) { 
    int result;
    struct log_in_list *entry;
    struct log_in_list *tmp;
    list_for_each_entry_safe(entry, tmp, &log_list, log_list_element) {
        result = func(entry->data);
        if (result==-1){
            return -1;
        }
    }
    return 0;
}
