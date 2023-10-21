CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-lrdmacm -libverbs
TARGET=cm-client
SRC=cm_client.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
