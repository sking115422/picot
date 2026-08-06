CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_GNU_SOURCE
POLICY_CFLAGS = $(shell pkg-config --cflags libcjson)
POLICY_LIBS   = $(shell pkg-config --libs libcjson)

BINS = hello_supervisor envelope_supervisor test_policy

all: $(BINS)

hello_supervisor: hello_supervisor.c
	$(CC) $(CFLAGS) -o $@ $<

envelope_supervisor: envelope_supervisor.c policy_engine.c policy_engine.h \
                     target_reader.c target_reader.h \
                     argv_tokenize.c argv_tokenize.h
	$(CC) $(CFLAGS) $(POLICY_CFLAGS) -o $@ \
		envelope_supervisor.c policy_engine.c target_reader.c argv_tokenize.c \
		$(POLICY_LIBS)

test_policy: test_policy.c policy_engine.c policy_engine.h
	$(CC) $(CFLAGS) $(POLICY_CFLAGS) -o $@ test_policy.c policy_engine.c $(POLICY_LIBS)

clean:
	rm -f $(BINS)

.PHONY: all clean
