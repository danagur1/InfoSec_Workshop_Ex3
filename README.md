# HW3-stateless firewall
## kernel-side
compiling and running: make; insmod firewall.ko
including 5 .c files and 4 .h files
1. main.c: contain the basic init and exit funciton of the kernel module
2. hooking_functions.c: contain the registration, unregistration and hook function
3. log_show_functions.c: contain all the functions related to the driver responsible for showing log
4. log_clear_functions.c: contain all the functions related to the driver responsible for clearing log
5. rules_functions.c: contain all the functions related to the driver responsible for loading and showing rules
6. manage_log_list.c: contain the log list data structure and the functions related to it
## user-side
running: python3 main.py
including 
1. main.py: main program that check the arguments to the program and call the relevant function
2. log_functions.py: contain all the functions related to show and clear the log including parsing and using drivers
3. rules_functions.py: contain all the functions related to the load and show of the rule table including parsing and using drivers