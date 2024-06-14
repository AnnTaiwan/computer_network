# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Source files
SRCS = client.c server.c tcp.c cal.c

# Header files
HDRS = tcp.h cal.h

# Object files
OBJS = tcp.o cal.o client.o server.o 

# Executable names
CLIENT_EXE = client
SERVER_EXE = server

# Default target
all: $(CLIENT_EXE) $(SERVER_EXE)

# Compile client
$(CLIENT_EXE): client.o tcp.o
	$(CC) $(CFLAGS) -o $@ client.o tcp.o

# Compile server
$(SERVER_EXE): server.o tcp.o cal.o
	$(CC) $(CFLAGS) -o $@ server.o tcp.o cal.o -lm

# Compile client.o
client.o: client.c $(HDRS)
	$(CC) $(CFLAGS) -c client.c

# Compile server.o
server.o: server.c $(HDRS)
	$(CC) $(CFLAGS) -c server.c

# Compile tcp.o
tcp.o: tcp.c $(HDRS)
	$(CC) $(CFLAGS) -c tcp.c

# Compile cal.o
cal.o: cal.c $(HDRS)
	$(CC) $(CFLAGS) -c cal.c 
	
# Clean up the project
clean:
	rm -f $(CLIENT_EXE) $(SERVER_EXE) $(OBJS)

.PHONY: all clean

