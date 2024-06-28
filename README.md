# Linux kernel module
This project implements a Linux kernel module that acts as a stateful firewall.
Features:
•	Stateful Packet Inspection: Tracks TCP connection states to ensure correct communication
•	Data Stream Inspection: Blocks HTTP responses of type "text/csv" or "application/zip" 
•	Intrusion Prevention System (IPS): Protects against CVE-2023-26876 SQL injection vulnerability  
•	Data Leak Prevention (DLP): Blocks outgoing C code over SMTP and HTTP 
## Installation and Running
### Kernel-side
```Shell
make; insmod firewall.ko
```
### User-side
```Shell
python3 main.py  
python3 http_proxy.py  
python3 ftp_proxy.py
```
### Command-line Arguments
•	`show_rules`: Display the current firewall rules  
•	`load_rules <file>`: Load rules from a specified file  
•	`show_log`: Display the current log  
•	`clear_log`: Clear the current log  
•	`show_conns`: Display the current connection table  
### Example Rule File
Firewall rules can be configured by providing an input file. An example file is `rules example.txt`:
```plaintext
loopback any 127.0.0.1/8 127.0.0.1/8 any any any any accept
GW_attack any any 10.0.2.15/32 any any any any drop
spoof1 in 10.0.1.1/24 any any any any any drop
spoof2 out 10.0.2.2/24 any any any any any drop
telnet1 out 10.0.1.1/24 any TCP >1023 23 any accept
telnet2 in any 10.0.1.1/24 TCP 23 >1023 yes accept
default any any any any any any any drop
```
## Projectt Files
### Kernel-side
•	main.c: Contains the basic init and exit function of the kernel module  
•	hooking_functions.c: Contains the registration, unregistration and hook function  
•	log_show_functions.c: Contains all the functions related to the driver responsible for showing log  
•	log_clear_functions.c: Contains all the functions related to the driver responsible for clearing log  
•	rules_functions.c: Contains all the functions related to the driver responsible for loading and showing rules  
•	manage_log_list.c: Contains the log list data structure and the functions related to it  
•	fw.h: Include useful structures and constants  
•	conn_show_functions.c: Contains all the functions related to the driver responsible for showing the connection table  
•	proxy.c: Contains the proxy functionality for passing packets to and from user-level  
### User-side
•	main.py: Main program that check the arguments to the program and call the relevant function  
•	log_functions.py: Contains all the functions related to show and clear the log including parsing and using drivers  
•	rules_functions.py: Contains all the functions related to the load and show of the rule table and using drivers  
•	conn_function.py: Contains all the functions related to the connection table including parsing and using drivers  
•	parse_fields.py and reverse_parse_fields.py: Contains parsing function used by functions related to communication with kernel-side  
•	dlp.py: Contains functions related to Data Leak Prevention  
•	http_proxy and ftp_proxy.py: Servers that listen to packets sent by the kernel-level, decides their verdict, then if accept send them to destination  
## Usage Example
```Shell
make  
sudo insmod firewall.ko  
python3 main.py load_rules "rules example.txt"
python3 http_proxy.py
python3 main.py show_rules
# Displays the list of currently loaded firewall rules
python3 main.py show_conns
# Shows the current connection table, including source and destination IPs, and connection states
python3 main.py show_log
#  Outputs the log entries, detailing packet information and reasons for any blocks or drops
```
