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
CFLAGS_BASE = -std=c11 -D_GNU_SOURCE -g -fno-common -fno-strict-overflow -pthread $(WARN)

ifeq ($(SAN),1)
  BUILD   = build-san
  OPT     = -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined -DIMDB_FE_CHECKS
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

TSRC    = $(wildcard tests/unit/*.c)
TOBJ    = $(TSRC:tests/unit/%.c=$(BUILD)/tobj/%.o) $(BUILD)/tobj/acrypto.o $(BUILD)/tobj/afsum.o
TBIN    = $(BUILD)/test_unit

.PHONY: all lint test unit san tsan ct fuzz fuzz-run bench whole index-sum mem-split join-cost clean integration faults soak

AUDIT   = $(BUILD)/imagedb-audit
ASRC    = tools/audit/audit.c tools/audit/acrypto.c tools/audit/afsum.c

all: $(BIN) $(AUDIT)

# The independent verifier shares no code with src/ (see tools/audit/acrypto.h).
$(AUDIT): $(ASRC) tools/audit/acrypto.h tools/audit/afsum.h | $(BUILD)/obj
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

$(BIN): $(BUILD)/obj/main.o $(LIB)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/obj/main.o: src/main.c $(HDR) | $(BUILD)/obj
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tobj/%.o: tests/unit/%.c $(HDR) tests/unit/test.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -Wno-missing-prototypes -Wno-deprecated-declarations -Wno-format-truncation -c $< -o $@

$(BUILD)/tobj/acrypto.o: tools/audit/acrypto.c tools/audit/acrypto.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/tobj/afsum.o: tools/audit/afsum.c tools/audit/afsum.h | $(BUILD)/tobj
	$(CC) $(CFLAGS) -c $< -o $@

$(TBIN): $(TOBJ) $(LIB)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lcrypto

$(BUILD)/obj $(BUILD)/tobj:
	mkdir -p $@

unit: $(TBIN) $(AUDIT)
	IMDB_AUDIT_BIN=$(AUDIT) $(TBIN)
	IMDB_NO_SIMD=1 $(TBIN) kernels

# The second pass also runs every parallel loop inline (IMDB_THREADS=1): results
# must not depend on the thread count.
# Growth must wipe the block it leaves (util.c): no plain realloc in the engine.
# File system calls go through fsio.c (imdb_io_*), where the tests inject faults.
IOCALLS = open|openat|read|pread|write|pwrite|fsync|fdatasync|ftruncate|renameat|rename|unlinkat|unlink|mkdir|mkdirat|fstat|fstatat|flock|fdopendir|opendir|readdir
ALLOCS  = malloc|calloc|aligned_alloc|strdup|strndup|posix_memalign
lint:
	@! grep -nE '(^|[^_a-z])realloc[[:space:]]*\(' src/*.c src/*.h || { echo "realloc in src/: use imdb_realloc_array"; exit 1; }
	@! grep -nE '(^|[^_a-zA-Z0-9.>"])($(IOCALLS))\(' $(filter-out src/fsio.c src/main.c,$(wildcard src/*.c)) || \
	  { echo "raw file system call in src/: use the imdb_io_* wrappers (fsio.h)"; exit 1; }
	@! grep -nE '(^|[^_a-zA-Z0-9.>"])($(ALLOCS))\(' $(filter-out src/util.c src/main.c,$(wildcard src/*.c)) || \
	  { echo "raw allocation in src/: use the imdb_alloc* helpers (util.h; the tests fail them at will)"; exit 1; }

# The fault group (t_fault.c) runs in the first pass only: the second repeats the kernels in their
# C references, which the fault handling does not depend on.
test: lint $(TBIN) $(BIN) $(AUDIT) $(FORGE)
	IMDB_AUDIT_BIN=$(AUDIT) $(TBIN)
	IMDB_FAULT_SKIP=1 IMDB_NO_SIMD=1 IMDB_THREADS=1 $(TBIN)
	bash tests/integration/run.sh $(BIN)
	IMDB_NO_SIMD=1 IMDB_THREADS=1 bash tests/integration/run.sh $(BIN)
	bash tests/integration/audit_reject.sh $(BIN)

integration: $(BIN) $(AUDIT) $(FORGE)
	bash tests/integration/run.sh $(BIN)
	bash tests/integration/audit_reject.sh $(BIN)

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
	$(MAKE) SAN=1 build-san/test_unit build-san/imagedb build-san/imagedb-audit build-san/imdb-forge
	IMDB_AUDIT_BIN=build-san/imagedb-audit $(SANRUN) build-san/test_unit
	IMDB_FAULT_SKIP=1 IMDB_NO_SIMD=1 IMDB_THREADS=1 $(SANRUN) build-san/test_unit
	bash tests/integration/run.sh build-san/imagedb
	IMDB_NO_SIMD=1 IMDB_THREADS=1 bash tests/integration/run.sh build-san/imagedb
	bash tests/integration/audit_reject.sh build-san/imagedb

FUZZ_TARGETS = $(patsubst fuzz/%.c,build-fuzz/%,$(wildcard fuzz/fuzz_*.c))
FUZZ_ASM     = $(ASMSRC:asm/%.asm=build-fuzz/asm/%.o)
FUZZ_FLAGS   = -std=c11 -D_GNU_SOURCE -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
               -DIMDB_HAVE_ASM -DIMDB_FUZZ -DIMDB_FE_CHECKS -Wall -Wextra -Werror -Wno-unused-parameter
fuzz: $(FUZZ_TARGETS)

build-fuzz/asm/%.o: asm/%.asm asm/common.inc
	mkdir -p build-fuzz/asm
	$(NASM) -f elf64 -I asm/ $< -o $@

build-fuzz/%: fuzz/%.c fuzz/fuzz_common.h $(SRC) $(HDR) $(FUZZ_ASM)
	clang $(FUZZ_FLAGS) $< $(SRC) $(FUZZ_ASM) -o $@ -pthread

# 60 s per target from the seed corpus (override: make fuzz-run FUZZ_SECONDS=600)
FUZZ_SECONDS ?= 60
fuzz-run: fuzz $(BIN) $(FORGE)
	bash fuzz/make_corpus.sh $(BIN) build-fuzz/corpus
	@for t in frame stream segment manifest sql codec ed25519 tseg; do \
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

# cpu.c and every file its dispatch table names (the C kernels and the references): the two links
# that list their sources by hand (the tsan pool driver, make ct) take it whole, so a new kernel
# joins this list (chacha20x8.c was missed once, 2026-10-26)
KERNEL_SRC = src/cpu.c src/sha256.c src/sha256x8.c src/chacha20x8.c src/vendor/monocypher/monocypher.c

# Data-race check (clang ThreadSanitizer; not part of the four-configuration matrix):
# the whole unit suite with the C kernels, plus the pool tests on their own.
TSAN_FLAGS = -std=c11 -D_GNU_SOURCE -g -O1 -fsanitize=thread -fno-omit-frame-pointer -pthread -Wno-deprecated-declarations
tsan:
	mkdir -p build-tsan
	clang $(TSAN_FLAGS) $(filter-out src/main.c,$(wildcard src/*.c)) $(wildcard src/vendor/monocypher/*.c) \
	  $(TSRC) tools/audit/acrypto.c tools/audit/afsum.c -o build-tsan/test_unit -lcrypto
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
