#include "fw.h"

void init_conn_list(void);

int add_to_conn_list(conn_row_t *conn);

void remove_all_from_conn_list(void);

int func_for_conn_list(int (*func)(conn_row_t));

conn_row_t *find_identical_conn(conn_row_t *conn, int (*compare_conns)(conn_row_t*, conn_row_t*));

int get_conn_list_length(void);