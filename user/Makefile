obj-m += firewall.o

firewall-objs := main.o rules_functions.o hooking_functions.o manage_log_list.o log_clear_functions.o log_show_functions.o manage_conn_list.o conn_show_functions.o proxy.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
