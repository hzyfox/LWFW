#General Purpose Makefile for Linux Kernel module by guoqingbo

KERN_DIR = /usr/src/linux-headers-3.13.0-77-generic
#KERN_DIR = /usr/src/$(shell uname -r)
#KERN_DIR = /lib/modules/$(shell uname -r)/build
#test-objs := test_mod.o test_mod2.o
test-objs := mylwfw.o
all:
	make -C $(KERN_DIR) M=$(shell pwd) modules
	gcc -Wall -o myusr  myusr.c 

clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
	rm -f myusr *.o

obj-m += test.o
