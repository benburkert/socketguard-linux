obj-m := socketguard.o

socketguard-y += context.o main.o noise.o proto.o recv.o send.o

default:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

modules_install:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules_install

test:
	$(MAKE) -C tests clisrv
	$(MAKE) -C tests clisrv-epoll
	$(MAKE) -C tests clisrv-rekey
