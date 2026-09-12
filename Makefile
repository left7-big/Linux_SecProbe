KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC ?= gcc

obj-m += secprobe.o

.PHONY: all module user clean

all: module user

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

user: user_ctrl

user_ctrl: user_ctrl.c common.h
	$(CC) -Wall -Wextra -O2 -o $@ user_ctrl.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f user_ctrl
