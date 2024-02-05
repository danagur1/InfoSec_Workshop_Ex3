#ifndef LOG_STRUCT_H
#define LOG_STRUCT_H

void init_log_list(void);

int add_to_log_list(log_row_t *log);

void remove_all_from_log_list(void);

int func_for_log_list(int (*func)(log_row_t *));

log_row_t *find_identical_log(log_row_t *log, int (*compare_logs)(log_row_t *log1, log_row_t *log2));

#endif
