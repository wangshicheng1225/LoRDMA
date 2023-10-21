CC = g++

CFLAGS = -std=c++11 -g -O2 -Wno-unused-parameter -Wno-unused-but-set-variable

LDFLAGS = -g
LDLIBS = -libverbs

TARGET = prober

SRCS = prober.cpp loadpcap.cpp 

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)
