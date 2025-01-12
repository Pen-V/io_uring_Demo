CROSS_COMPILE = riscv64-linux-gnu-
ARCH = riscv
CC = $(CROSS_COMPILE)gcc
CFLAGS = -g -Og -I./include
LDFLAGS = -g
SRCS = uring_test.c

OBJS = $(SRCS:%.c=%.o)
BINS = $(OBJS:%.o=%)

all: urings

urings: $(OBJS)
	$(CC) $(CFLAGS) -o a.out $(OBJS)

.c.o: $(SRCS)
	$(CC) -c $(CFLAGS) $*.c

clean:
	rm -f *.o run
	rm -f *.out
