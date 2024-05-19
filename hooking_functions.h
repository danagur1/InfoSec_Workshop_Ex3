#include "fw.h"
int register_hook_pre(rule_t* rule_table, int *rule_table_size);
void unregister_hook_pre(void);
int check_match(conn_row_t *row_for_check_match, conn_row_t *current_row_check);
