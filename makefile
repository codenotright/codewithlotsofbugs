# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -std=c++11 -Wall -Iinclude

# Linker flags (for OpenSSL)
LDFLAGS = -lssl -lcrypto

# Source files
SRCS = $(wildcard src/*.cpp)

# Object files for main1 and main2
OBJS_COMMON = $(patsubst src/%.cpp, obj/%.o, $(SRCS))

OBJS_DEMO_SERVER = $(OBJS_COMMON) obj/demo_server.o
OBJS_DEMO_CLIENT = $(OBJS_COMMON) obj/demo_client.o

# Executable names
TARGET1 = server
TARGET2 = client

# Default target
all: $(TARGET1) $(TARGET2)

# Rule to link the first executable
$(TARGET1): $(OBJS_DEMO_SERVER)
	$(CXX) $(OBJS_DEMO_SERVER) -o $(TARGET1) $(LDFLAGS)

# Rule to link the second executable
$(TARGET2): $(OBJS_DEMO_CLIENT)
	$(CXX) $(OBJS_DEMO_CLIENT) -o $(TARGET2) $(LDFLAGS)

# Rule to compile source files into object files
obj/%.o: src/%.cpp
	@mkdir -p obj
	$(CXX) $(CXXFLAGS) -c $< -o $@
	echo "Finished compiling $<"

# Rule to compile main files into object files
obj/%.o: %.cpp
	@mkdir -p obj
	$(CXX) $(CXXFLAGS) -c $< -o $@
	echo "Finished compiling $<"

# Clean up build files
clean:
	rm -rf obj $(TARGET1) $(TARGET2)

# Phony targets
.PHONY: all clean

