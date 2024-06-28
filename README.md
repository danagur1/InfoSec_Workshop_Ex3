# Linux kernel module
Kernel level firewall with statful packet inspection  
•	Tracking the state of TCP connections and enforce its correctness  
•	Inspection the DATA as a stream- blocking HTTP response of type “text/csv” or “application/zip”  
•	IPS- protection against CVE-2023-26876 SQL injection vulnerability  
•	Data Leak Prevention- block outgoing C code over SMTP and HTTP  
## kernel-side
### compiling and running
make; insmod firewall.ko
### files
including 6 .c files and 5 .h files
1. main.c: contain the basic init and exit funciton of the kernel module
2. hooking_functions.c: contain the registration, unregistration and hook function
3. log_show_functions.c: contain all the functions related to the driver responsible for showing log
4. log_clear_functions.c: contain all the functions related to the driver responsible for clearing log
5. rules_functions.c: contain all the functions related to the driver responsible for loading and showing rules
6. manage_log_list.c: contain the log list data structure and the functions related to it
7. fw.h: include useful structures and constants
8. conn_show_functions.c: contain all the functions related to the driver responsible for showing the connection table
9. proxy.c: contain the proxy stuff that pass packets to user-level and from user-level
## user-side
### running
python3 main.py  
python3 http_proxy.py  
python3 ftp_proxy.py
### files
1. main.py: main program that check the arguments to the program and call the relevant function
2. log_functions.py: contain all the functions related to show and clear the log including parsing and using drivers
3. rules_functions.py: contain all the functions related to the load and show of the rule table and using drivers
4. conn_function.py: contain all the functions related to the connection table including parsing and using drivers
5. parse_fields.py and reverse_parse_fields.py: contain parsing function used by functions related to communication with kernel-side
6. dlp.py: contain functions related to Data Leak Prevention
7. http_proxy and ftp_proxy.py: servers that listen to packets sent by the kernel-level, decides their verdict, then if accept send them to destination
