# Makefile for compiling client and server programs with OpenSSL support

# Compiler to use
CXX = g++

# Compiler flags
#CXXFLAGS = -Wall -Wextra -std=c++11
CXXFLAGS = -w -std=c++11

# OpenSSL include and library paths (adjust if necessary)
OPENSSL_INCLUDE = -I/usr/include/openssl
OPENSSL_LIB = -L/usr/lib -lssl -lcrypto

# Targets
TARGETS = client server

# Source files
CLIENT_SRC = client.cpp
SERVER_SRC = server.cpp

# Executable files
CLIENT_EXE = client
SERVER_EXE = server

# Default rule
all: $(TARGETS)

# Rule for client
client: $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) $(OPENSSL_INCLUDE) -o $(CLIENT_EXE) $(CLIENT_SRC) $(OPENSSL_LIB)

# Rule for server
server: $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) $(OPENSSL_INCLUDE) -o $(SERVER_EXE) $(SERVER_SRC) $(OPENSSL_LIB)

# Clean rule to remove executables
clean:
	rm -f $(CLIENT_EXE) $(SERVER_EXE)

# Phony targets
.PHONY: all clean

