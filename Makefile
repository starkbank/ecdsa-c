# starkecdsa
#
#   make                static library
#   make shared         shared library exporting only starkecdsa_*
#   make test           build and run the suite against the static archive
#   make test-shared    build the public-API-only suite against the shared library
#   make check-exports  fail if the shared library exports anything else
#   make install        headers, archive, shared library and pkg-config file
#
# SECP256K1_PREFIX points at a libsecp256k1 install; the default covers a
# Homebrew prefix on either architecture and a plain /usr/local. Windows is
# not covered by this Makefile: build the sources with the STARKECDSA_BUILD_SHARED
# define and link bcrypt.lib (see README).

CC ?= cc
AR ?= ar
PREFIX ?= /usr/local
DESTDIR ?=

SECP256K1_PREFIX ?= $(shell \
	for p in /opt/homebrew/opt/secp256k1 /usr/local/opt/secp256k1 /usr/local /usr; do \
		if [ -f "$$p/include/secp256k1.h" ]; then echo $$p; break; fi; \
	done)

# Mandatory flags stay apart from the user-facing CFLAGS: a command-line
# CFLAGS overrides every makefile assignment, and losing -fvisibility=hidden
# would silently widen the exported surface. -fPIC is mandatory too, and for
# the static archive as well as the shared object: core-c and the SDKs link
# libstarkecdsa.a into their own shared libraries, and ELF refuses non-PIC
# objects there (PC32 relocation against secp256k1_nonce_function_rfc6979).
CFLAGS ?= -O2
TEST_CFLAGS ?= -O1 -g
REQUIRED_CFLAGS = -std=c99 -pedantic -Wall -Wextra -Wshadow -Wconversion -Wstrict-prototypes \
          -Wmissing-prototypes -Wpointer-arith -Wwrite-strings -Wcast-qual \
          -fvisibility=hidden -fPIC -MMD -MP
ALL_CFLAGS = $(REQUIRED_CFLAGS) $(CFLAGS)
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
DEPENDS = $(OBJECTS:.o=.d)

ABI_VERSION = 1
VERSION = $(shell sed -n 's/^\#define STARKECDSA_VERSION "\(.*\)"/\1/p' include/starkecdsa.h)

# The export list is enforced at link time, not only by -fvisibility=hidden:
# a statically linked libsecp256k1 would otherwise be re-exported wholesale.
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  SHARED_NAME = libstarkecdsa.dylib
  SHARED_FLAGS = -dynamiclib -install_name @rpath/$(SHARED_NAME) -Wl,-exported_symbols_list,exports.txt
  NM_EXPORTS = nm -gU $(SHARED_NAME) | awk '{print $$3}' | sed 's/^_//'
else
  SHARED_NAME = libstarkecdsa.so.$(ABI_VERSION)
  SHARED_FLAGS = -shared -Wl,-soname,$(SHARED_NAME) -Wl,--version-script,exports.map -Wl,--exclude-libs,ALL
  NM_EXPORTS = nm -D --defined-only $(SHARED_NAME) | awk '$$2 != "A" {print $$3}' | sed 's/@@.*//'
  LDLIBS += -pthread
endif

.PHONY: all shared test test-shared check-exports install clean

all: libstarkecdsa.a

libstarkecdsa.a: $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

shared: ALL_CFLAGS += -DSTARKECDSA_BUILD_SHARED
shared: $(SOURCES) exports.txt exports.map
	$(CC) $(ALL_CFLAGS) $(CPPFLAGS) $(SHARED_FLAGS) -o $(SHARED_NAME) $(SOURCES) $(LDFLAGS) $(LDLIBS)
ifneq ($(UNAME),Darwin)
	ln -sf $(SHARED_NAME) libstarkecdsa.so
endif

# Derived from the public header, so the exported set cannot drift from it.
exports.txt: include/starkecdsa.h
	grep -oE 'starkecdsa_[a-z_0-9]+\(' include/starkecdsa.h | sed 's/($$//' | sort -u | sed 's/^/_/' > $@

exports.map: include/starkecdsa.h
	printf 'STARKECDSA_%s {\n  global: starkecdsa_*;\n  local: *;\n};\n' $(ABI_VERSION) > $@

%.o: %.c
	$(CC) $(ALL_CFLAGS) $(CPPFLAGS) -c $< -o $@

-include $(DEPENDS)

test: libstarkecdsa.a
	$(CC) -std=c99 $(TEST_CFLAGS) -Wall -Wextra $(CPPFLAGS) -DTEST_FIXTURE_DIR='"tests"' \
		-o tests/run tests/test.c libstarkecdsa.a $(LDFLAGS) $(LDLIBS)
	./tests/run

# Built against include/starkecdsa.h and the shared library only: proves the
# public surface is sufficient and that the export list is what it claims.
test-shared: shared check-exports
	$(CC) -std=c99 $(TEST_CFLAGS) -Wall -Wextra -Iinclude -DTEST_FIXTURE_DIR='"tests"' \
		-o tests/run-shared tests/public.c -L. -lstarkecdsa -Wl,-rpath,. $(LDFLAGS) $(LDLIBS)
	./tests/run-shared

check-exports: shared
	@$(NM_EXPORTS) | grep -v '^starkecdsa_' > exports.unexpected || true
	@if [ -s exports.unexpected ]; then echo "unexpected exported symbols:"; cat exports.unexpected; exit 1; fi
	@echo "exports: $$($(NM_EXPORTS) | grep -c '^starkecdsa_') symbols, all starkecdsa_*"

libstarkecdsa.pc:
	printf 'prefix=%s\nlibdir=$${prefix}/lib\nincludedir=$${prefix}/include\n\nName: starkecdsa\nDescription: ECDSA over secp256k1 for the Stark Bank and Stark Infra APIs\nVersion: %s\nRequires.private: libsecp256k1\nLibs: -L$${libdir} -lstarkecdsa\nCflags: -I$${includedir}\n' $(PREFIX) $(VERSION) > $@

install: libstarkecdsa.a shared libstarkecdsa.pc
	install -d $(DESTDIR)$(PREFIX)/include $(DESTDIR)$(PREFIX)/lib/pkgconfig
	install -m 644 include/starkecdsa.h $(DESTDIR)$(PREFIX)/include/
	install -m 644 libstarkecdsa.a $(DESTDIR)$(PREFIX)/lib/
	install -m 755 $(SHARED_NAME) $(DESTDIR)$(PREFIX)/lib/
ifneq ($(UNAME),Darwin)
	ln -sf $(SHARED_NAME) $(DESTDIR)$(PREFIX)/lib/libstarkecdsa.so
endif
	install -m 644 libstarkecdsa.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/

clean:
	rm -f $(OBJECTS) $(DEPENDS) libstarkecdsa.a libstarkecdsa.dylib libstarkecdsa.so libstarkecdsa.so.$(ABI_VERSION)
	rm -f tests/run tests/run-shared exports.txt exports.map exports.unexpected libstarkecdsa.pc
	rm -rf tests/run.dSYM tests/run-shared.dSYM
