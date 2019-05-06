SRCS=popcorn-notify.c parse-symbol.c
BIN=popcorn-notify
all: $(BIN)

$(BIN): $(SRCS)
	gcc -g $(SRCS) -o $@

install:
	install $(BIN) /usr/local/bin/$(BIN)

clean:
	rm $(BIN)
