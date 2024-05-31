# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11 -Wall -Iinclude

# Linker flags (for OpenSSL)
LDFLAGS = -lssl -lcrypto

# Source files
SRCS = $(wildcard src/*.cpp)

# Object files for main1 and main2
OBJS_COMMON = $(SRCS:.cpp=.o)

OBJS_DEMO_SERVER = $(OBJS_COMMON) demo_server.o
OBJS_DEMO_CLIENT = $(OBJS_COMMON) demo_client.o

# Executable names
TARGET1 = server
TARGET2 = client

# Default target
all: $(TARGET1) $(TARGET2)

# Rule to link the first executable
$(TARGET1): $(OBJS_MAIN1)
	$(CXX) $(OBJS_DEMO_SERVER) -o $(TARGET1) $(LDFLAGS)

# Rule to link the second executable
$(TARGET2): $(OBJS_MAIN2)
	$(CXX) $(OBJS_DEMO_CLIENT) -o $(TARGET2) $(LDFLAGS)

# Rule to compile source files into object files
src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


# Rule to compile source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJS_COMMON) demo_server.o demo_client.o $(TARGET1) $(TARGET2)

clear:
	rm -f $(OBJS_COMMON) $(TARGET1) $(TARGET2)

# Phony targets
.PHONY: all clean

