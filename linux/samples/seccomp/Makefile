LIBS = -lseccomp -lpthread
CFLAGS = -g -Wall
SRCS  = $(wildcard *.c)
OBJS  = $(SRCS:.c=.o)
PROGS = $(SRCS:.c=)
all: $(PROGS)
$(PROGS): $(OBJS)
	$(CC) -o $@ $@.o $(LIBS)
clean:
	rm -f $(PROGS) $(OBJS)
#test1: test1.c
#	$(CC) -o $@ $^ $(OPT) $(LIBS)
