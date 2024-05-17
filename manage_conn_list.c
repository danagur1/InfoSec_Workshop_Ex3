#include <linux/klist.h>
#include <linux/slab.h> // for kmalloc and kfree
#include "fw.h"

struct conn_in_list {
    conn_row_t *data;
    struct list_head conn_list_element;
};

static LIST_HEAD(conn_list);
int conn_list_length;

void init_conn_list(void) {
    conn_list_length = 0;
    INIT_LIST_HEAD(&conn_list);
}

int add_to_conn_list(conn_row_t *conn) {
    struct conn_in_list *entry;
    printk(KERN_INFO "checking addition. adding a connecion row with source ip %d\n", conn->src_ip);
    if (!conn){
        printk("failed cause of conn=NULL");
        return 0;
    }
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;
    entry->data = conn;
    INIT_LIST_HEAD(&entry->conn_list_element);
    list_add_tail(&entry->conn_list_element, &conn_list);
    conn_list_length++;
    return 0;
}

void remove_all_from_conn_list(void) {
    struct conn_in_list *entry, *next;
    list_for_each_entry_safe(entry, next, &conn_list, conn_list_element) {
        list_del(&entry->conn_list_element);
        kfree(entry->data);
        kfree(entry);
    }
    conn_list_length = 0;
}

int get_conn_list_length(void) {
    return conn_list_length;
}

conn_row_t *find_identical_conn(conn_row_t *conn, int (*compare_conns)(conn_row_t *, conn_row_t *)) {
    struct conn_in_list *entry;
    struct conn_in_list *tmp;
    list_for_each_entry_safe(entry, tmp, &conn_list, conn_list_element) {
        if(compare_conns(entry->data, conn)){
            return entry->data;
        }
    }
    return NULL;
}

int func_for_conn_list(int (*func)(conn_row_t)) {
    int result;
    struct conn_in_list *entry;
    struct conn_in_list *tmp;
    list_for_each_entry_safe(entry, tmp, &conn_list, conn_list_element) {
        result = func(*(entry->data));
        if (result==-1){
            return -1;
        }
    }
    return 0;
}
