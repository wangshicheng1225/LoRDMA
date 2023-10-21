CFLAGS:= -Wall -Wno-unused-variable -Wno-unused-but-set-variable
CFLAGS+=-O2 -pthread
LDFLAGS:=-g
LDLIBS:=-libverbs


all: burster-period


burster-period:	burster_period.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.out $^ $(LOADLIBES) $(LDLIBS)

clean:
	$(RM) *.o *.out debugger


.PHONY: all clean
