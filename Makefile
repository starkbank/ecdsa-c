# starkecdsa
#
#   make            static library
#   make shared     shared library with only starkecdsa_* exported
#   make test       build and run the suite
#
# SECP256K1_PREFIX points at a libsecp256k1 install; the default covers a
# Homebrew prefix on either architecture and a plain /usr/local.

CC ?= cc
AR ?= ar

SECP256K1_PREFIX ?= $(shell \
	for p in /opt/homebrew/opt/secp256k1 /usr/local/opt/secp256k1 /usr/local /usr; do \
		if [ -f "$$p/include/secp256k1.h" ]; then echo $$p; break; fi; \
	done)

CFLAGS ?= -O2
CFLAGS += -std=c99 -pedantic -Wall -Wextra -Wshadow -Wconversion -Wstrict-prototypes \
          -Wmissing-prototypes -Wpointer-arith -Wwrite-strings -Wcast-qual \
          -fvisibility=hidden
CPPFLAGS += -Iinclude -Iellipticcurve -I$(SECP256K1_PREFIX)/include
LDFLAGS += -L$(SECP256K1_PREFIX)/lib
LDLIBS += -lsecp256k1

SOURCES = \
	ellipticcurve/curve.c \
	ellipticcurve/ecdsa.c \
	ellipticcurve/privateKey.c \
	ellipticcurve/publicKey.c \
	ellipticcurve/signature.c \
	ellipticcurve/utils/base64.c \
	ellipticcurve/utils/binary.c \
	ellipticcurve/utils/der.c \
	ellipticcurve/utils/pem.c \
	ellipticcurve/utils/sha256.c

OBJECTS = $(SOURCES:.c=.o)

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  SHARED_NAME = libstarkecdsa.dylib
  SHARED_FLAGS = -dynamiclib -install_name @rpath/$(SHARED_NAME)
else
  SHARED_NAME = libstarkecdsa.so.1
  SHARED_FLAGS = -shared -Wl,-soname,$(SHARED_NAME)
endif

.PHONY: all shared test clean

all: libstarkecdsa.a

libstarkecdsa.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

shared: CFLAGS += -fPIC -DSTARKECDSA_BUILD_SHARED
shared: $(SOURCES)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(SHARED_FLAGS) -o $(SHARED_NAME) $(SOURCES) $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

test: libstarkecdsa.a
	$(CC) -std=c99 -O1 -g -Wall -Wextra $(CPPFLAGS) -DTEST_FIXTURE_DIR='"tests"' \
		-o tests/run tests/test.c libstarkecdsa.a $(LDFLAGS) $(LDLIBS)
	./tests/run

clean:
	rm -f $(OBJECTS) libstarkecdsa.a libstarkecdsa.dylib libstarkecdsa.so.1 tests/run
	rm -rf tests/run.dSYM
