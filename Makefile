CFLAGS = -Wall -Wextra -Werror -pedantic
BINS = ipmap 

all: CFLAGS += -O3
all: $(BINS)

.PHONY: debug
debug: CFLAGS += -fsanitize=address -fsanitize=undefined -O0 -g
debug: $(BINS)

ipmap: ipmap.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -rf $(BINS) *.dSYM
