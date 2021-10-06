# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_TARGETS := dtn_tune

CC ?= gcc

USER_C := ${USER_TARGETS:=.c}

EXTRA_DEPS +=

all: $(USER_TARGETS) 

.PHONY: clean 

clean:
	rm -f $(USER_TARGETS) 

$(USER_TARGETS): %: %.c   
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ \
	 $< $(LIBS)

