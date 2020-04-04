clisrv: clisrv.o
	cc clisrv.o -o $@ -I $(PWD) -lpthread

clisrv-epoll: clisrv-epoll.o
	cc clisrv-epoll.o -o $@ -I $(PWD) -lpthread

%.o: %.c
	cc -c $< -o $@ -I $(PWD) -lpthread
