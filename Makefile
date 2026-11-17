# imagedb build
#   make            release build (hardened, NASM kernels)
#   make test       unit tests + integration tests
#   make san        AddressSanitizer + UBSan build and unit tests
#   make fuzz       libFuzzer harnesses (clang)
#   make bench      micro-benchmarks
#   make NOASM=1    portable C only (no NASM)

CC      ?= cc
NASM    ?= nasm
BUILD   ?= build
SAN     ?=
NOASM   ?=

WARN    = -Wall -Wextra -Werror -Wformat=2 -Werror=format-security -Wvla -Wshadow \
          -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wundef -Wcast-qual \
          -Wimplicit-fallthrough -Wno-unused-parameter
CFLAGS_BASE = -std=c11 -D_GNU_SOURCE -g -fno-common -fno-strict-overflow -ffp-contract=off -pthread $(WARN) \
              -ffile-prefix-map=$(CURDIR)=. # P2: reproducible builds (the path the tree is built in is in no output)

ifeq ($(SAN),1)
  BUILD   = build-san
  OPT     = -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined -DIMDB_FE_CHECKS -DIMDB_STORE_CHECKS
  LDSAN   = -fsanitize=address,undefined
  HARDEN  =
else
  OPT     = -O2
  HARDEN  = -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fcf-protection -fPIE
  LDSAN   =
endif
LDHARDEN = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

ifeq ($(NOASM),1)
  ASMDEF  =
  ASMSRC  =
else
  ASMDEF  = -DIMDB_HAVE_ASM
  ASMSRC  = $(wildcard asm/*.asm)
endif

CFLAGS  = $(CFLAGS_BASE) $(OPT) $(HARDEN) $(ASMDEF)
LDFLAGS = $(LDHARDEN) $(LDSAN) -pthread

SRC     = $(filter-out src/main.c,$(wildcard src/*.c)) $(wildcard src/vendor/monocypher/*.c)
OBJ     = $(SRC:src/%.c=$(BUILD)/obj/%.o) $(ASMSRC:asm/%.asm=$(BUILD)/obj/%.asm.o)
HDR     = $(wildcard src/*.h src/vendor/monocypher/*.h)
LIB     = $(BUILD)/libimagedb.a
BIN     = $(BUILD)/imagedb
SERVER  = $(BUILD)/imagedb-server
CLIENTBIN = $(BUILD)/imagedb-client
CLIENTLIB = $(BUILD)/libimagedb-client.a

TSRC    = $(wildcard tests/unit/*.c)
TOBJ    = $(TSRC:tests/unit/%.c=$(BUILD)/tobj/%.o) $(BUILD)/tobj/acrypto.o $(BUILD)/tobj/afsum.o $(BUILD)/tobj/abind.o \
          $(BUILD)/tobj/apq.o $(BUILD)/tobj/aice.o $(BUILD)/tobj/wire.o $(BUILD)/tobj/conv.o $(BUILD)/tobj/srv.o \
          $(BUILD)/tobj/client.o $(BUILD)/tobj/tls.o $(BUILD)/tobj/spool.o $(BUILD)/tobj/netres.o
TBIN    = $(BUILD)/test_unit

.PHONY: all server install-server uninstall-server lint test unit san tsan ct fuzz fuzz-run bench whole index-sum mem-split join-cost workload clean integration faults soak oracle install uninstall parquet-check iceberg-check

AUDIT   = $(BUILD)/imagedb-audit
ASRC    = tools/audit/audit.c tools/audit/acrypto.c tools/audit/afsum.c tools/audit/abind.c tools/audit/apq.c tools/audit/aice.c

all: $(BIN) $(AUDIT)

# N1b, N1c: the server (build/imagedb-server, which links OpenSSL: TLS on TCP), out of all so that `make` builds the
# engine with libc and pthread alone; the suite builds it (its order-only prerequisite: t_server runs it)
server: $(SERVER) $(CLIENTBIN) $(CLIENTLIB) $(BUILD)/client-link

# make install (P1 A1): the CLI and the auditor, the static library, the README and the licence; DESTDIR stages
# it (a package). A sanitizer build (SAN=1) is never installed.
PREFIX  ?= /usr/local
ifneq ($(SAN),)
install:
	@echo "make install: not a sanitizer build (SAN=1)"; exit 1
else
install: $(BIN) $(AUDIT) $(LIB)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/share/doc/imagedb
	install -m 0755 $(BIN) $(AUDIT) $(DESTDIR)$(PREFIX)/bin/
	install -m 0644 $(LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 0644 README.md LICENSE $(DESTDIR)$(PREFIX)/share/doc/imagedb/
endif

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/imagedb $(DESTDIR)$(PREFIX)/bin/imagedb-audit $(DESTDIR)$(PREFIX)/lib/libimagedb.a
	rm -f $(DESTDIR)$(PREFIX)/share/doc/imagedb/README.md $(DESTDIR)$(PREFIX)/share/doc/imagedb/LICENSE
	-rmdir $(DESTDIR)$(PREFIX)/share/doc/imagedb

# N1d-2: the server, its shell and the C client's library and headers (they link OpenSSL: out of `make install`, which
# installs the engine alone). The headers keep their directories, so their relative includes hold:
# #include <imagedb/client/imagedb_client.h> with -I$(PREFIX)/include, then -limagedb-client -lssl -lcrypto -pthread
CLIENT_HDRS = client/imagedb_client.h server/wire.h src/util.h src/limits.h
ifneq ($(SAN),)
install-server:
	@echo "make install-server: not a sanitizer build (SAN=1)"; exit 1
else
install-server: $(SERVER) $(CLIENTBIN) $(CLIENTLIB)
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib $(addprefix $(DESTDIR)$(PREFIX)/include/imagedb/,client server src)
	install -m 0755 $(SERVER) $(CLIENTBIN) $(DESTDIR)$(PREFIX)/bin/
	install -m 0644 $(CLIENTLIB) $(DESTDIR)$(PREFIX)/lib/
	for h in $(CLIENT_HDRS); do install -m 0644 $$h $(DESTDIR)$(PREFIX)/include/imagedb/$$h || exit 1; done
endif

uninstall-server:
	rm -f $(DESTDIR)$(PREFIX)/bin/imagedb-server $(DESTDIR)$(PREFIX)/bin/imagedb-client $(DESTDIR)$(PREFIX)/lib/libimagedb-client.a
	for h in $(CLIENT_HDRS); do rm -f $(DESTDIR)$(PREFIX)/include/imagedb/$$h; done
	-rmdir $(addprefix $(DESTDIR)$(PREFIX)/include/imagedb/,client server src) $(DESTDIR)$(PREFIX)/include/imagedb

# The independent verifier shares no code with src/ (see tools/audit/acrypto.h).
$(AUDIT): $(ASRC) tools/audit/acrypto.h tools/audit/afsum.h tools/audit/abind.h tools/audit/apq.h tools/audit/aice.h | $(BUILD)/obj
	$(CC) $(CFLAGS) $(ASRC) -o $@ $(LDFLAGS)

# Test-only: builds hostile inputs and fuzz seeds (may use engine code).
FORGE   = $(BUILD)/imdb-forge
$(FORGE): tests/tools/forge.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes $< $(LIB) -o $@ $(LDFLAGS)

$(BUILD)/obj/%.o: src/%.c $(HDR) | $(BUILD)/obj
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Ed25519: the masked table scans of constant-time signing vectorize (SSE2), about 20% faster.
$(BUILD)/obj/ed25519.o: CFLAGS += -ftree-vectorize

$(BUILD)/obj/%.asm.o: asm/%.asm asm/common.inc | $(BUILD)/obj
	$(NASM) -f elf64 -I asm/ $< -o $@

$(LIB): $(OBJ)
	rm -f $@
	ar rcs $@ $^

$(BIN): $(BUILD)/obj/main.o $(BUILD)/obj/cli_run.o $(LIB)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/obj/main.o: src/main.c cli/run.h $(HDR) | $(BUILD)/obj
	$(CC) $(CFLAGS) -c $< -o $@

# N1d-2: the SQL shell's runner (cli/run.c), build/imagedb's and build/imagedb-client's: never in libimagedb.a
$(BUILD)/obj/cli_run.o: cli/run.c cli/run.h $(HDR) | $(BUILD)/obj
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tobj/%.o: tests/unit/%.c $(HDR) tests/unit/test.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -Wno-missing-prototypes -Wno-deprecated-declarations -Wno-format-truncation -c $< -o $@

$(BUILD)/tobj/acrypto.o: tools/audit/acrypto.c tools/audit/acrypto.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tobj/afsum.o: tools/audit/afsum.c tools/audit/afsum.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

# F5: the auditor's Parquet reader, which t_pq gives the files the engine's refuses (a chunk past the file)
$(BUILD)/tobj/apq.o: tools/audit/apq.c tools/audit/apq.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

# F5c: the auditor's Iceberg readers, which t_ice reads the engine's layer with
$(BUILD)/tobj/aice.o: tools/audit/aice.c tools/audit/aice.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

# N1a: the server's protocol (server/wire.c, outside src/: the engine's library links no network code)
# N1b: the engine's results and parameters to and from the wire (server/conv.c)
$(BUILD)/tobj/conv.o: server/conv.c server/conv.h server/wire.h $(HDR) | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

# N1b: the server (server/srv.c: the engine thread, connections, authentication) and the C client (client/)
$(BUILD)/tobj/srv.o: server/srv.c server/srv.h server/conv.h server/wire.h server/tls.h server/spool.h $(HDR) | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tobj/client.o: client/client.c client/imagedb_client.h server/wire.h server/tls.h $(HDR) | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

# N1d: COPY's spool files (server/spool.c, the one file of the server making its own file system calls)
$(BUILD)/tobj/spool.o: server/spool.c server/spool.h server/wire.h $(HDR) | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

# N1c: TLS 1.3 (server/tls.c, the one file of the server and the client that includes OpenSSL's headers)
$(BUILD)/tobj/tls.o: server/tls.c server/tls.h server/wire.h $(HDR) | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

$(SERVER): server/main.c server/srv.h $(BUILD)/tobj/srv.o $(BUILD)/tobj/conv.o $(BUILD)/tobj/wire.o $(BUILD)/tobj/tls.o $(BUILD)/tobj/spool.o $(LIB)
	$(CC) $(CFLAGS) server/main.c $(BUILD)/tobj/srv.o $(BUILD)/tobj/conv.o $(BUILD)/tobj/wire.o $(BUILD)/tobj/tls.o $(BUILD)/tobj/spool.o $(LIB) -o $@ \
	  $(LDFLAGS) -lssl -lcrypto

# N1d-2: the C client's library (client/imagedb_client.h): the client, the codec, TLS and what they take of the engine's
# sources (util, sha256, scram, fsio); OpenSSL at the application's link
$(CLIENTLIB): $(BUILD)/tobj/client.o $(BUILD)/tobj/wire.o $(BUILD)/tobj/tls.o $(BUILD)/obj/util.o $(BUILD)/obj/sha256.o \
              $(BUILD)/obj/scram.o $(BUILD)/obj/fsio.o
	rm -f $@ && ar rcs $@ $^

# N1d-2: imagedb-client, the network shell: the runner (cli/run.c), the result's conversion (conv.c), the client's
# library, and libimagedb.a for the splitter, the renderer and the zones (it opens no database)
# N1d-2: an application of the client's library alone (no libimagedb.a): the library holds all it needs
$(BUILD)/client-link: tests/client_link/main.c client/imagedb_client.h $(CLIENTLIB)
	$(CC) $(CFLAGS) tests/client_link/main.c $(CLIENTLIB) -o $@ $(LDFLAGS) -lssl -lcrypto

$(CLIENTBIN): cli/shell.c cli/run.h cli/netres.h client/imagedb_client.h $(BUILD)/obj/cli_run.o $(BUILD)/tobj/netres.o \
              $(BUILD)/tobj/conv.o $(CLIENTLIB) $(LIB)
	$(CC) $(CFLAGS) cli/shell.c $(BUILD)/obj/cli_run.o $(BUILD)/tobj/netres.o $(BUILD)/tobj/conv.o $(CLIENTLIB) $(LIB) -o $@ \
	  $(LDFLAGS) -lssl -lcrypto

# N1d-2: a result rebuilt from the wire (cli/netres.c): the shell's, and the suite's round trip (t_conv)
$(BUILD)/tobj/netres.o: cli/netres.c cli/netres.h server/conv.h server/wire.h $(HDR) | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tobj/wire.o: server/wire.c server/wire.h $(HDR) | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tobj/abind.o: tools/audit/abind.c tools/audit/abind.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

$(TBIN): $(TOBJ) $(LIB) | $(SERVER) # N1b: t_server runs the binary beside the suite's own
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lssl -lcrypto

$(BUILD)/obj $(BUILD)/tobj:
	mkdir -p $@

unit: $(TBIN) $(AUDIT)
	IMDB_AUDIT_BIN=$(AUDIT) $(TBIN)
	IMDB_NO_SIMD=1 $(TBIN) kernels

# The second pass also runs every parallel loop inline (IMDB_THREADS=1): results
# must not depend on the thread count.
# Growth must wipe the block it leaves (util.c): no plain realloc in the engine.
# File system calls go through fsio.c (imdb_io_*), where the tests inject faults.
# Frees go through imdb_free (util.c), where the heap's counter credits them.
IOCALLS = open|openat|openat2|syscall|read|pread|write|pwrite|fsync|fdatasync|ftruncate|renameat|rename|unlinkat|unlink|mkdir|mkdirat|fstat|fstatat|flock|fdopendir|opendir|readdir
ALLOCS  = malloc|calloc|aligned_alloc|strdup|strndup|posix_memalign
lint:
	@! grep -nE '(^|[^_a-z])realloc[[:space:]]*\(' src/*.c src/*.h || { echo "realloc in src/: use imdb_realloc_array"; exit 1; }
	@! grep -nE '(^|[^_a-zA-Z0-9.>"])($(IOCALLS))\(' $(filter-out src/fsio.c src/main.c,$(wildcard src/*.c)) || \
	  { echo "raw file system call in src/: use the imdb_io_* wrappers (fsio.h)"; exit 1; }
	@! grep -nE '(^|[^_a-zA-Z0-9.>"])($(ALLOCS))\(' $(filter-out src/util.c src/main.c,$(wildcard src/*.c)) || \
	  { echo "raw allocation in src/: use the imdb_alloc* helpers (util.h; the tests fail them at will)"; exit 1; }
	@! grep -nE '(^|[^_a-zA-Z0-9.>"])free\(' $(filter-out src/util.c src/main.c,$(wildcard src/*.c)) || \
	  { echo "raw free in src/: use imdb_free (util.h: the heap's counter credits it)"; exit 1; }
	@! grep -ln '#include "tz.h"' $(filter-out src/tz.c src/db.c $(wildcard src/sql*.c),$(wildcard src/*.c src/*.h)) tools/audit/*.c || \
	  { echo "tz.h outside tz.c, db.c and sql*.c: nothing a replica, VERIFY or the auditor recomputes reads a zone"; exit 1; }
	@! grep -nE '(^|[^_a-zA-Z0-9.>"])(localtime|localtime_r|mktime|tzset|timelocal|strftime)\(|getenv\("TZ"\)' src/*.c src/*.h tools/audit/*.c || \
	  { echo "the host's time zone read: zones are named, never the process's (tz.h)"; exit 1; }
	@! grep -nE '(^|[^_a-z])realloc[[:space:]]*\(' /dev/null server/*.c server/*.h client/*.c client/*.h || { echo "realloc in server/ or client/"; exit 1; }
	@! grep -nE '(^|[^_a-zA-Z0-9.>"])($(ALLOCS)|free)\(' /dev/null $(filter-out server/wire.c,$(wildcard server/*.c)) \
	  $(wildcard client/*.c) || \
	  { echo "raw allocation in server/ or client/: imdbw_alloc and imdbw_free (wire.h: counted, never the engine's)"; exit 1; }
	@! grep -nE '(^|[^_a-zA-Z0-9.>"])imdb_(alloc|alloc_array|realloc_array|alloc_aligned|free)\(' /dev/null server/wire.c \
	  server/srv.c $(wildcard client/*.c) || \
	  { echo "the engine's allocator in the wire codec, the server's threads or the client: its ceiling is process-wide (docs/n1-design.md §2)"; exit 1; }
	@! grep -nE '#[[:space:]]*include[[:space:]]*<openssl/' /dev/null src/*.c src/*.h $(filter-out server/tls.c,$(wildcard server/*.c server/*.h)) \
	  client/*.c client/*.h || { echo "an OpenSSL header outside server/tls.c (N1c: libimagedb.a and build/imagedb link none)"; exit 1; }
	@sh tools/check_options.sh # every SET, option and IMDB_ variable src/ reads is in the README's table (P1 A1)

# The fault group (t_fault.c) runs in the first pass only: the second repeats the kernels in their
# C references, which the fault handling does not depend on. The third evicts at every publish (IMDB_EVICT=eager,
# stage 3b): every read below the memory floor then goes to the lake, as a long-running copy's would.
# The fourth and fifth keep no segment image between operations (IMDB_SEGCACHE=tiny, stage 3c-1), without the eager
# mode and with it: every image is read again at its next use, under the held versions' ends and below the floor.
test: lint $(TBIN) $(BIN) $(AUDIT) $(FORGE) $(SERVER) $(CLIENTBIN)
	IMDB_AUDIT_BIN=$(AUDIT) $(TBIN)
	IMDB_FAULT_SKIP=1 IMDB_NO_SIMD=1 IMDB_THREADS=1 $(TBIN)
	IMDB_FAULT_SKIP=1 IMDB_EVICT=eager IMDB_AUDIT_BIN=$(AUDIT) $(TBIN)
	IMDB_FAULT_SKIP=1 IMDB_SEGCACHE=tiny IMDB_AUDIT_BIN=$(AUDIT) $(TBIN)
	IMDB_FAULT_SKIP=1 IMDB_SEGCACHE=tiny IMDB_EVICT=eager IMDB_AUDIT_BIN=$(AUDIT) $(TBIN)
	bash tests/integration/run.sh $(BIN)
	IMDB_NO_SIMD=1 IMDB_THREADS=1 bash tests/integration/run.sh $(BIN)
	IMDB_EVICT=eager bash tests/integration/run.sh $(BIN)
	IMDB_SEGCACHE=tiny bash tests/integration/run.sh $(BIN)
	bash tests/integration/audit_reject.sh $(BIN)
	bash tests/integration/client.sh $(BIN) # N1d-2: imagedb-client against imagedb sql

integration: $(BIN) $(AUDIT) $(FORGE) $(SERVER) $(CLIENTBIN)
	bash tests/integration/run.sh $(BIN)
	bash tests/integration/audit_reject.sh $(BIN)
	bash tests/integration/client.sh $(BIN)

# Every fault point (not every 7th) of every scenario, on the build disk instead of tmpfs.
faults: $(TBIN) $(AUDIT)
	mkdir -p $(BUILD)/tmp
	IMDB_AUDIT_BIN=$(AUDIT) IMDB_FAULT_FULL=1 IMDB_FAULT_TMP=$(BUILD)/tmp $(TBIN) fault

# Hours of churn over a fixed live set, the writer killed at random and restarted, memory and disk sampled
# (tests/soak/soak.sh; deferred.md D8): not in the matrix. SOAK_MINUTES, SOAK_LIVE; IMDB_SOAK_* knobs in the script.
SOAK_MINUTES ?= 120
SOAK_LIVE ?= 100000
soak: $(BIN) $(LIB) $(AUDIT)
	mkdir -p $(BUILD)/tmp
	IMDB_SOAK_TMP=$(BUILD)/tmp bash tests/soak/soak.sh $(BIN) $(SOAK_MINUTES) $(SOAK_LIVE)

# Sanitizer runtimes of clang <= 16 / gcc 11 can fault-loop at startup when the
# kernel uses 32 bits of mmap randomisation (Linux 6.x); run them without ASLR.
SANRUN = setarch $(shell uname -m) -R

san: lint
	$(MAKE) SAN=1 build-san/test_unit build-san/imagedb build-san/imagedb-audit build-san/imdb-forge build-san/imagedb-server \
	  build-san/imagedb-client
	IMDB_AUDIT_BIN=build-san/imagedb-audit $(SANRUN) build-san/test_unit
	IMDB_FAULT_SKIP=1 IMDB_NO_SIMD=1 IMDB_THREADS=1 $(SANRUN) build-san/test_unit
	IMDB_FAULT_SKIP=1 IMDB_EVICT=eager IMDB_AUDIT_BIN=build-san/imagedb-audit $(SANRUN) build-san/test_unit
	IMDB_FAULT_SKIP=1 IMDB_SEGCACHE=tiny IMDB_AUDIT_BIN=build-san/imagedb-audit $(SANRUN) build-san/test_unit
	IMDB_FAULT_SKIP=1 IMDB_SEGCACHE=tiny IMDB_EVICT=eager IMDB_AUDIT_BIN=build-san/imagedb-audit $(SANRUN) build-san/test_unit
	bash tests/integration/run.sh build-san/imagedb
	IMDB_NO_SIMD=1 IMDB_THREADS=1 bash tests/integration/run.sh build-san/imagedb
	IMDB_EVICT=eager bash tests/integration/run.sh build-san/imagedb
	IMDB_SEGCACHE=tiny bash tests/integration/run.sh build-san/imagedb
	bash tests/integration/audit_reject.sh build-san/imagedb
	bash tests/integration/client.sh build-san/imagedb

FUZZ_TARGETS = $(patsubst fuzz/%.c,build-fuzz/%,$(wildcard fuzz/fuzz_*.c))
FUZZ_ASM     = $(ASMSRC:asm/%.asm=build-fuzz/asm/%.o)
FUZZ_FLAGS   = -std=c11 -D_GNU_SOURCE -g -O1 -ffp-contract=off -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
               -DIMDB_HAVE_ASM -DIMDB_FUZZ -DIMDB_FE_CHECKS -DIMDB_STORE_CHECKS -Wall -Wextra -Werror -Wno-unused-parameter
fuzz: $(FUZZ_TARGETS)

build-fuzz/asm/%.o: asm/%.asm asm/common.inc
	mkdir -p build-fuzz/asm
	$(NASM) -f elf64 -I asm/ $< -o $@

# F5: the auditor's Parquet reader against the engine's on the same bytes (fuzz_apq): both, in one binary, each its own code
build-fuzz/fuzz_apq: fuzz/fuzz_apq.c fuzz/fuzz_common.h tools/audit/apq.c tools/audit/apq.h tools/audit/acrypto.c $(SRC) $(HDR) $(FUZZ_ASM)
	@mkdir -p build-fuzz
	clang $(FUZZ_FLAGS) fuzz/fuzz_apq.c tools/audit/apq.c tools/audit/acrypto.c $(SRC) $(FUZZ_ASM) -o $@ -pthread

# F5c: the auditor's readers of the Iceberg layer (fuzz_aice), against the engine's writers (icecodec.c) for round trips
build-fuzz/fuzz_aice: fuzz/fuzz_aice.c fuzz/fuzz_common.h tools/audit/aice.c tools/audit/aice.h $(SRC) $(HDR) $(FUZZ_ASM)
	@mkdir -p build-fuzz
	clang $(FUZZ_FLAGS) fuzz/fuzz_aice.c tools/audit/aice.c $(SRC) $(FUZZ_ASM) -o $@ -pthread

# N1a: the server's protocol (server/wire.c) on any bytes: what a decoder takes is its one encoding
build-fuzz/fuzz_wire: fuzz/fuzz_wire.c fuzz/fuzz_common.h server/wire.c server/wire.h $(SRC) $(HDR) $(FUZZ_ASM)
	@mkdir -p build-fuzz
	clang $(FUZZ_FLAGS) fuzz/fuzz_wire.c server/wire.c $(SRC) $(FUZZ_ASM) -o $@ -pthread

# P2 S7b: the auditor's view binder alone (it shares nothing with src/)
build-fuzz/fuzz_abind: fuzz/fuzz_abind.c tools/audit/abind.c tools/audit/abind.h
	@mkdir -p build-fuzz
	clang $(FUZZ_FLAGS) fuzz/fuzz_abind.c tools/audit/abind.c -o $@

build-fuzz/%: fuzz/%.c fuzz/fuzz_common.h $(SRC) $(HDR) $(FUZZ_ASM)
	clang $(FUZZ_FLAGS) $< $(SRC) $(FUZZ_ASM) -o $@ -pthread

# 60 s per target from the seed corpus (override: make fuzz-run FUZZ_SECONDS=600)
FUZZ_SECONDS ?= 60
fuzz-run: fuzz $(BIN) $(FORGE)
	bash fuzz/make_corpus.sh $(BIN) build-fuzz/corpus
	@for t in frame stream segment manifest sql codec ed25519 tseg backup expr csv abind role parquet apq aice wire; do \
	  mkdir -p build-fuzz/work/$$t; \
	  if ! $(SANRUN) build-fuzz/fuzz_$$t -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1 -rss_limit_mb=2048 \
	       -artifact_prefix=build-fuzz/crash-$$t- build-fuzz/work/$$t build-fuzz/corpus/$$t \
	       > build-fuzz/log-$$t.txt 2>&1; then \
	    echo "fuzz_$$t: FAILED (see build-fuzz/log-$$t.txt)"; tail -30 build-fuzz/log-$$t.txt; exit 1; \
	  fi; \
	  echo "fuzz_$$t: $$(grep -E '^Done' build-fuzz/log-$$t.txt), no crashes"; \
	done

BENCH = $(BUILD)/bench
$(BENCH): bench/bench.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes bench/bench.c $(LIB) -o $@ $(LDFLAGS)

bench: $(BENCH)
	$(BENCH)

# Whole-engine benchmarks against SQLite and PostgreSQL at equal durability (deferred.md R8). Only
# this benchmark links them; the engine never does. bench/whole.sh needs root (the governor
# window, a private PostgreSQL instance run as the postgres user) and a quiet machine.
WHOLE = $(BUILD)/whole
$(WHOLE): bench/whole.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -I /usr/include/postgresql bench/whole.c $(LIB) -o $@ $(LDFLAGS) -lsqlite3 -lpq

# The same, with MySQL, MariaDB, SQL Server and DuckDB too (the user's request, 2026-10-26):
# libmysqlclient for both MySQL servers, unixODBC with Microsoft's ODBC Driver 18, DuckDB's library
# in DUCKDB_DIR; their headers by -isystem, so warnings inside them stay theirs. bench/whole.sh,
# given this binary, also runs those engines (MySQL, MariaDB and SQL Server in containers).
DUCKDB_DIR ?= /opt/duckdb
WHOLE_EXT = $(BUILD)/whole-ext
$(WHOLE_EXT): bench/whole.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -DWITH_EXT -I /usr/include/postgresql -isystem /usr/include/mysql \
	  -isystem $(DUCKDB_DIR) bench/whole.c $(LIB) -o $@ $(LDFLAGS) -lsqlite3 -lpq -lmysqlclient -lodbc \
	  -L $(DUCKDB_DIR) -lduckdb -Wl,-rpath,$(DUCKDB_DIR)

PROBE = $(BUILD)/fsync_probe
$(PROBE): bench/fsync_probe.c
	$(CC) $(CFLAGS) bench/fsync_probe.c -o $@ $(LDFLAGS)

# preallocation measured (docs/commit-speed.md): durable commits through the engine, built against
# either tree; and P against F as write patterns on this disk
CLAT = $(BUILD)/commit_lat
$(CLAT): bench/commit_lat.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Isrc bench/commit_lat.c $(LIB) -o $@ $(LDFLAGS)
GPROBE = $(BUILD)/group_probe
$(GPROBE): bench/group_probe.c
	$(CC) $(CFLAGS) bench/group_probe.c -o $@ $(LDFLAGS)

# the disk's own pauses and slow flushes during a run (docs/open-items-2026-10-26.md, A): bench/whole.sh
# runs it beside the engines when it is next to the driver
DEVSTALL = $(BUILD)/devstall
$(DEVSTALL): bench/devstall.c
	$(CC) $(CFLAGS) bench/devstall.c -o $@ $(LDFLAGS)

whole: $(WHOLE) $(PROBE) $(DEVSTALL)
	sh bench/whole.sh $(WHOLE)

# all ten: the five above, then PostgreSQL in a container, MySQL, MariaDB, SQL Server, DuckDB (docker)
whole-ext: $(WHOLE_EXT) $(PROBE) $(DEVSTALL)
	sh bench/whole.sh $(WHOLE_EXT)

# F5 (docs/f5-design.md): imagedb's Parquet files read by DuckDB's library, the one reader from outside on this machine
# (the user, 2026-11-13: "DuckDB is fine"); opt-in, outside the matrix, test-only: imagedb links nothing of it. Its
# scratch in tmpfs (the user's choice for test scratch: give rm -rf /dev/shm/imdb-* at the session's end).
PQCHECK = $(BUILD)/pqcheck
$(PQCHECK): tests/parquet_check/pqcheck.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -isystem $(DUCKDB_DIR) tests/parquet_check/pqcheck.c $(LIB) -o $@ $(LDFLAGS) \
	  -L $(DUCKDB_DIR) -lduckdb -Wl,-rpath,$(DUCKDB_DIR)
# its second part (pqengine): DuckDB reads the segments the engine itself wrote (every type at its edges, NULLs, an
# ALTER, an ERASE's stubs) against imagedb's own SELECT; a fresh directory beneath the scratch each run
PQENGINE = $(BUILD)/pqengine
$(PQENGINE): tests/parquet_check/pqengine.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -isystem $(DUCKDB_DIR) tests/parquet_check/pqengine.c $(LIB) -o $@ $(LDFLAGS) \
	  -L $(DUCKDB_DIR) -lduckdb -Wl,-rpath,$(DUCKDB_DIR)
parquet-check: $(PQCHECK) $(PQENGINE)
	mkdir -p /dev/shm/imdb-pqcheck && $(PQCHECK) /dev/shm/imdb-pqcheck
	$(PQENGINE) /dev/shm/imdb-pqcheck

# F5c (docs/f5c-design.md section 8): the Iceberg v3 layer read by DuckDB's iceberg and avro extensions (the user's yes,
# 2026-11-14: INSTALL avro; INSTALL iceberg), every snapshot of every publication against imagedb's own answer AS OF it;
# opt-in, outside the matrix, test-only (it links the auditor's JSON reader, aice.c, to read the metadata)
ICECHECK = $(BUILD)/icecheck
$(ICECHECK): tests/iceberg_check/icecheck.c tools/audit/aice.c tools/audit/aice.h $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -isystem $(DUCKDB_DIR) tests/iceberg_check/icecheck.c tools/audit/aice.c $(LIB) -o $@ \
	  $(LDFLAGS) -L $(DUCKDB_DIR) -lduckdb -Wl,-rpath,$(DUCKDB_DIR)
iceberg-check: $(ICECHECK)
	mkdir -p /dev/shm/imdb-icecheck && $(ICECHECK) /dev/shm/imdb-icecheck

# The SQL oracle (tests/oracle, P0): imagedb against SQLite in process and, through tests/oracle/run.sh, PostgreSQL,
# MySQL, MariaDB and SQL Server in private containers, every answer compared. Test-only: it links their clients (the
# user's yes, 2026-11-01); the engine links none of them.
ORACLE = $(BUILD)/oracle
$(ORACLE): tests/oracle/oracle.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -I /usr/include/postgresql -isystem /usr/include/mysql \
	  tests/oracle/oracle.c $(LIB) -o $@ $(LDFLAGS) -lsqlite3 -lpq -lmysqlclient -lodbc
oracle: $(ORACLE)

# CREATE INDEX measured (docs/bench-2026-10-23.md, the addendum): build/index_sum DIR, a new DIR
ISUM = $(BUILD)/index_sum
$(ISUM): bench/index_sum.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes bench/index_sum.c $(LIB) -o $@ $(LDFLAGS)

index-sum: $(ISUM)

# where imagedb's memory goes (docs/bench-2026-10-24.md): build/mem_split DIR, a new DIR
MSPLIT = $(BUILD)/mem_split
$(MSPLIT): bench/mem_split.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes bench/mem_split.c $(LIB) -o $@ $(LDFLAGS)

mem-split: $(MSPLIT)

# the join planner's costs (sql_exec.c join_choose): build/join_cost DIR, a new DIR
JCOST = $(BUILD)/join_cost
$(JCOST): bench/join_cost.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes bench/join_cost.c $(LIB) -o $@ $(LDFLAGS)

join-cost: $(JCOST)

# Q2 (P1): interleaved sessions, a scaling series, the checkpoint's stall (docs/plan-p1.md): build/workload MODE ...
WORKLOAD = $(BUILD)/workload
$(WORKLOAD): bench/workload.c $(LIB) $(HDR)
	$(CC) $(CFLAGS) -Wno-missing-prototypes bench/workload.c $(LIB) -o $@ $(LDFLAGS)

workload: $(WORKLOAD)

# cpu.c and every file its dispatch table names (the C kernels and the references): the two links
# that list their sources by hand (the tsan pool driver, make ct) take it whole, so a new kernel
# joins this list (chacha20x8.c was missed once, 2026-10-26)
KERNEL_SRC = src/cpu.c src/sha256.c src/sha256x8.c src/chacha20x8.c src/vendor/monocypher/monocypher.c

# Data-race check (clang ThreadSanitizer; not part of the four-configuration matrix):
# the whole unit suite with the C kernels, plus the pool tests on their own.
TSAN_FLAGS = -std=c11 -D_GNU_SOURCE -g -O1 -ffp-contract=off -fsanitize=thread -fno-omit-frame-pointer -pthread -Wno-deprecated-declarations \
             -ftrivial-auto-var-init=pattern
tsan:
	mkdir -p build-tsan
	clang $(TSAN_FLAGS) $(filter-out src/main.c,$(wildcard src/*.c)) $(wildcard src/vendor/monocypher/*.c) \
	  $(TSRC) tools/audit/acrypto.c tools/audit/afsum.c tools/audit/abind.c tools/audit/apq.c tools/audit/aice.c server/wire.c server/conv.c server/srv.c server/tls.c server/spool.c cli/netres.c client/client.c -o build-tsan/test_unit -lssl -lcrypto
	clang $(TSAN_FLAGS) $(filter-out src/main.c,$(wildcard src/*.c)) $(wildcard src/vendor/monocypher/*.c) \
	  server/main.c server/srv.c server/conv.c server/wire.c server/tls.c server/spool.c -o build-tsan/imagedb-server -lssl -lcrypto # N1b: t_server runs it
	clang $(TSAN_FLAGS) tests/unit/t_pool.c tests/tsan/pool_main.c src/pool.c $(KERNEL_SRC) \
	  src/util.c src/fsio.c -o build-tsan/pool_test
	$(SANRUN) build-tsan/pool_test
	IMDB_FAULT_SKIP=1 $(SANRUN) build-tsan/test_unit

# Constant-time check of Ed25519 signing (clang MemorySanitizer as a taint tracker; not in the
# matrix). The signing run must be clean, and the canary, a deliberate branch on the secret, caught.
CT_SRC = tests/ct/ed25519_ct.c src/ed25519.c src/util.c src/fsio.c $(KERNEL_SRC) \
         src/vendor/monocypher/monocypher-ed25519.c
ct:
	mkdir -p build-ct
	clang -std=c11 -D_GNU_SOURCE -g -O2 -ftree-vectorize -fsanitize=memory -fsanitize-memory-track-origins=2 \
	  -fno-omit-frame-pointer -pthread $(CT_SRC) -o build-ct/ed25519_ct
	$(SANRUN) build-ct/ed25519_ct
	! $(SANRUN) build-ct/ed25519_ct --canary > build-ct/canary.log 2>&1
	grep -q "MemorySanitizer: use-of-uninitialized-value" build-ct/canary.log
	@echo "constant-time check: signing clean; the canary branch on the secret was caught"

clean:
	rm -rf build build-san build-fuzz build-tsan build-ct
