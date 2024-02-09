#define MAX_LOG_NODES 10 // Define the maximum number of nodes without dynamic allocation

static struct klist_node log_node_pool[MAX_LOG_NODES]; // Array to store nodes without dynamic allocation
static int log_node_count = 0; // Counter for the number of nodes in the array
static struct klist log_list;

void init_log_list(void) {
    printk(KERN_INFO "init of log list");
    klist_init(&log_list, NULL, NULL);
}

int add_to_log_list(log_row_t *log) {
    struct klist_node *node;

    if (log_node_count < MAX_LOG_NODES) { // If the array is not full
        node = &log_node_pool[log_node_count++]; // Take the next available node from the array
    } else { // If the array is full, dynamically allocate memory
        node = kmalloc(sizeof(struct klist_node), GFP_KERNEL);
        if (!node) {
            return -1;
        }
    }

    printk(KERN_INFO "adding to log list");
    klist_add_tail(node, &log_list);
    node->n_klist = log;
    return 0;
}

void remove_all_from_log_list(void) {
    struct klist_iter iter;
    struct klist_node *node;

    if (log_node_count > 0) { // If there are nodes in the array
        log_node_count = 0; // Reset the node count
    } else { // If the array is empty, use klist operations
        printk(KERN_INFO "clearing log list");
        klist_iter_init(&log_list, &iter);
        while ((node = klist_next(&iter)) != NULL) {
            klist_del(node);
            kfree(node);
        } 
        klist_iter_exit(&iter);
    }
}

log_row_t *find_identical_log(log_row_t *log, int (*compare_logs)(log_row_t*, log_row_t*)) {
    struct klist_iter iter;
    struct klist_node *node;

    if (log_node_count > 0) { // If there are nodes in the array
        for (int i = 0; i < log_node_count; ++i) {
            if (compare_logs(log_node_pool[i].n_klist, log) == 0) {
                return log_node_pool[i].n_klist;
            }
        }
        return NULL;
    } else { // If the array is empty, use klist operations
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
}

int func_for_log_list(int (*func)(log_row_t)) {
    struct klist_iter iter;
    struct klist_node *node;
    int func_result;

    if (log_node_count > 0) { // If there are nodes in the array
        for (int i = 0; i < log_node_count; ++i) {
            func_result = func(*((log_row_t*)(log_node_pool[i].n_klist)));
            if (func_result != 0) {
                return -1;
            }
        }
        return 0;
    } else { // If the array is empty, use klist operations
        printk(KERN_INFO "making functions on log list");
        klist_iter_init(&log_list, &iter);
        while ((node = klist_next(&iter)) != NULL) {
            func_result = func(*((log_row_t*)(node->n_klist)));
            if (func_result != 0) {
                klist_iter_exit(&iter);
                return -1;
            }
        }
        klist_iter_exit(&iter);
        return 0;
    }
}
