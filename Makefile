PREFIX=/usr/local

CFLAGS = -Wall -Wextra -Werror -pedantic
BINS = ipmap ipmap-query ipmap-viz

all: CFLAGS += -O3
all: $(BINS)

.PHONY: debug
debug: CFLAGS += -fsanitize=address -fsanitize=undefined -O0 -g
debug: $(BINS)

ipmap: ipmap.o util.o
	$(CC) $(CFLAGS) $^ -o $@

ipmap-query: ipmap-query.o util.o
	$(CC) $(CFLAGS) $^ -o $@

ipmap-viz: ipmap-viz.o util.o
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $?

.PHONY: install
install: all
	mkdir -p "${PREFIX}/bin"
	cp ipmap "${PREFIX}/bin/ipmap"
	chmod 755 "${PREFIX}/bin/ipmap"
	cp ipmap-query "${PREFIX}/bin/ipmap-query"
	chmod 755 "${PREFIX}/bin/ipmap-query"
	cp ipmap-query "${PREFIX}/bin/ipmap-viz"
	chmod 755 "${PREFIX}/bin/ipmap-viz"

.PHONY: clean
clean:
	rm -rf $(BINS) *.o *.dSYM
