obj-m += firewall.o
firewall-y := rules_functions.o log_clear_functions.o log_show_functions.o hooking_functions.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
