CC = g++
CFLAGS = -std=c++17 -Wall -Wextra -pthread
LDFLAGS = -lpcap

TARGET = ipk-L2L3-scan
TEST_TARGET = ipk-L2L3-scan-test

.DEFAULT_GOAL := all

SRC_DIR = src
INC_DIR = include
OBJ_DIR = build
TEST_DIR = tests

SOURCES = $(SRC_DIR)/main.cpp \
          $(SRC_DIR)/Scanner.cpp \
          $(SRC_DIR)/Results.cpp \
          $(SRC_DIR)/Packets.cpp \
          $(SRC_DIR)/SignalHandler.cpp

OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))

# Objekty pro testovací binárku (vše kromě main.o)
TEST_OBJECTS = $(OBJ_DIR)/Scanner.o $(OBJ_DIR)/Results.o $(OBJ_DIR)/Packets.o $(OBJ_DIR)/SignalHandler.o

all: $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(TARGET): $(OBJ_DIR) $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

$(OBJ_DIR)/test_main.o: $(TEST_DIR)/test_main.cpp
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

$(TEST_TARGET): $(OBJ_DIR) $(TEST_OBJECTS) $(OBJ_DIR)/test_main.o
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJECTS) $(OBJ_DIR)/test_main.o $(LDFLAGS)

test: $(TEST_TARGET)
	@./$(TEST_TARGET)

.PHONY: clean test

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(TEST_TARGET)

