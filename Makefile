CC ?= gcc
CFLAGS ?= -Wall -Wextra -std=c17 -O3 -pthread -Iinclude
LDFLAGS ?= -pthread

TARGET = TMiner
TEST_TARGET = test_runner

SRC = src/main.c \
      src/tminer.c \
      src/stratum.c \
      src/sha256.c

TEST_SRC = tests/test_sha256.c \
           src/sha256.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

test: $(TEST_SRC)
	$(CC) $(CFLAGS) $(TEST_SRC) -o $(TEST_TARGET) $(LDFLAGS)
	./$(TEST_TARGET)
	@rm -f $(TEST_TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET) *.o

.PHONY: all test clean
