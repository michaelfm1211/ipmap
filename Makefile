CFLAGS = -Wall -Wextra -Werror -pedantic
BINS = ipmap ipmap-query

all: CFLAGS += -O3
all: $(BINS)

.PHONY: debug
debug: CFLAGS += -fsanitize=address -fsanitize=undefined -O0 -g
debug: $(BINS)

ipmap: ipmap.o util.o
	$(CC) $(CFLAGS) $^ -o $@

ipmap-query: ipmap-query.o util.o
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $?

.PHONY: clean
clean:
	rm -rf $(BINS) *.o *.dSYM
