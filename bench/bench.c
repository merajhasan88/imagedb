/* imagedb benchmarks: SIMD/asm kernels vs C references, then the engine. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../src/cpu.h"
#include "../src/db.h"
#include "../src/lake.h"
#include "../src/lthash.h"
#include "../src/pool.h"
#include "../src/ed25519.h"
#include "../src/vendor/monocypher/monocypher-ed25519.h"
#include "../src/sha256.h"
#include "../src/sql.h"

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static volatile uint64_t g_sink;

static void kernels(void)
{
    const imdb_kernels *k = imdb_kern();
    enum { N = 1 << 20 };
    uint8_t *buf = malloc(N * 8);
    for (size_t i = 0; i < (size_t)N * 8; i++) buf[i] = (uint8_t)(i * 7 + 1) & 0x7f ? (uint8_t)((i * 7 + 1) & 0x7f) : 1;
    int64_t *col = (int64_t *)(void *)buf;
    uint64_t *bits = malloc(N / 8);
    double t0, dt;
    int reps = 20;

    t0 = now();
    for (int r = 0; r < reps; r++) g_sink += imdb_crc32c_ref(0, buf, N * 8);
    dt = now() - t0;
    double ref = (double)N * 8 * reps / dt / 1e9;
    t0 = now();
    for (int r = 0; r < reps; r++) g_sink += k->crc32c(0, buf, N * 8);
    dt = now() - t0;
    printf("  crc32c          C table %7.2f GB/s   %-14s %7.2f GB/s\n", ref, k->crc32c_name, (double)N * 8 * reps / dt / 1e9);

    imdb_lthash a, b;
    memset(&a, 1, sizeof a);
    memset(&b, 2, sizeof b);
    int lr = 200000;
    t0 = now();
    for (int r = 0; r < lr; r++) imdb_lthash_add_ref(a.v, b.v);
    dt = now() - t0;
    double lref = dt / lr * 1e9;
    t0 = now();
    for (int r = 0; r < lr; r++) k->lthash_add(a.v, b.v);
    dt = now() - t0;
    g_sink += a.v[3];
    printf("  lthash add      C       %7.1f ns/op   %-14s %7.1f ns/op (2 KiB vector)\n", lref, k->lthash_name, dt / lr * 1e9);

    for (int i = 0; i < N; i++) col[i] = (int64_t)((uint64_t)i * 2654435761u % 1000000);
    t0 = now();
    for (int r = 0; r < reps; r++) imdb_filter_range_i64_ref(col, N, 1000, 500000, bits);
    dt = now() - t0;
    double fref = (double)N * reps / dt / 1e6;
    t0 = now();
    for (int r = 0; r < reps; r++) k->filter_range_i64(col, N, 1000, 500000, bits);
    dt = now() - t0;
    printf("  range filter    C       %7.0f Mrow/s  %-14s %7.0f Mrow/s\n", fref, k->filter_name, (double)N * reps / dt / 1e6);

    int64_t out[2];
    t0 = now();
    for (int r = 0; r < reps; r++) imdb_sum_masked_i64_ref(col, bits, N, out);
    dt = now() - t0;
    double sref = (double)N * reps / dt / 1e6;
    g_sink += (uint64_t)out[0];
    t0 = now();
    for (int r = 0; r < reps; r++) k->sum_masked_i64(col, bits, N, out);
    dt = now() - t0;
    g_sink += (uint64_t)out[0];
    printf("  exact sum       C int128%7.0f Mrow/s  %-14s %7.0f Mrow/s\n", sref, k->sum_name, (double)N * reps / dt / 1e6);

    memset(buf, 'a', (size_t)N * 8);
    t0 = now();
    for (int r = 0; r < reps; r++) g_sink += imdb_ascii_prefix_ref(buf, (size_t)N * 8);
    dt = now() - t0;
    double aref = (double)N * 8 * reps / dt / 1e9;
    t0 = now();
    for (int r = 0; r < reps; r++) g_sink += k->ascii_prefix(buf, (size_t)N * 8);
    dt = now() - t0;
    printf("  utf8 ascii run  C       %7.2f GB/s   %-14s %7.2f GB/s\n", aref, k->utf8_name, (double)N * 8 * reps / dt / 1e9);

    uint8_t seed[40] = {1}, o[2048];
    int er = 3000;
    t0 = now();
    for (int r = 0; r < er; r++) {
        seed[9] = (uint8_t)r;
        imdb_lthash_expand_ref(seed, o);
    }
    dt = now() - t0;
    double eref = dt / er * 1e6;
    t0 = now();
    for (int r = 0; r < er * 5; r++) {
        seed[9] = (uint8_t)r;
        k->lthash_expand(seed, o);
    }
    dt = now() - t0;
    printf("  digest element  C       %7.1f us/row  %-14s %7.1f us/row (64 x SHA-256)\n", eref, k->expand_name, dt / (er * 5) * 1e6);
    /* digest_alg 2's element (the key's SHA-256, then 32 ChaCha20 blocks) and both state digests,
     * through lthash.c as the engine calls them */
    uint8_t cm[32] = {2}, d[32];
    imdb_lthash el, st;
    memset(&st, 0x5a, sizeof st);
    double per[4];
    for (int al = 0; al < 2; al++) {
        t0 = now();
        for (int r = 0; r < er * 5; r++) {
            cm[9] = (uint8_t)r;
            imdb_lthash_element(al ? IMDB_DIGEST_ALG_LTHASH16_TREE : IMDB_DIGEST_ALG_LTHASH16, cm, &el);
            g_sink += el.v[r & 1023];
        }
        per[al] = (now() - t0) / (er * 5) * 1e6;
        t0 = now();
        for (int r = 0; r < er * 5; r++) {
            st.v[r & 1023] ^= (uint16_t)r;
            imdb_lthash_digest(al ? IMDB_DIGEST_ALG_LTHASH16_TREE : IMDB_DIGEST_ALG_LTHASH16, &st, d);
            g_sink += d[0];
        }
        per[2 + al] = (now() - t0) / (er * 5) * 1e6;
    }
    printf("  element         alg 1   %7.1f us/row  alg 2 (%s) %7.1f us/row\n", per[0], k->expand2_name, per[1]);
    printf("  state digest    alg 1   %7.1f us      alg 2 (%s) %7.1f us (the tree)\n", per[2], k->sha8_name, per[3]);
    free(buf);
    free(bits);

    /* Ed25519 on a 52-byte message (a commit's signed descriptor): Monocypher, the
     * reference, against the fast path */
    uint8_t es[32] = {7}, msk[64], mpk[32], ea[32], ep[32], epk[32], msg[52] = {1}, sig[64];
    uint8_t tmp[32];
    memcpy(tmp, es, 32);
    crypto_ed25519_key_pair(msk, mpk, tmp);
    imdb_ed25519_expand(es, ea, ep, epk);
    int sr = 400;
    double ts[4];
    t0 = now();
    for (int r = 0; r < sr; r++) msg[0] = (uint8_t)r, crypto_ed25519_sign(sig, msk, msg, sizeof msg);
    ts[0] = (now() - t0) / sr * 1e6;
    t0 = now();
    for (int r = 0; r < sr; r++) msg[0] = (uint8_t)r, imdb_ed25519_sign(sig, ea, ep, epk, msg, sizeof msg);
    ts[1] = (now() - t0) / sr * 1e6;
    int good = 0;
    t0 = now();
    for (int r = 0; r < sr; r++) good += crypto_ed25519_check(sig, mpk, msg, sizeof msg) == 0;
    ts[2] = (now() - t0) / sr * 1e6;
    t0 = now();
    for (int r = 0; r < sr; r++) good += imdb_ed25519_verify(sig, epk, msg, sizeof msg);
    ts[3] = (now() - t0) / sr * 1e6;
    printf("  ed25519 sign    Monocypher %6.1f us     fast %6.1f us  (%.1fx)\n", ts[0], ts[1], ts[0] / ts[1]);
    printf("  ed25519 verify  Monocypher %6.1f us     fast %6.1f us  (%.1fx; %d/%d valid)\n", ts[2], ts[3], ts[2] / ts[3],
           good, 2 * sr);
    /* batches of 64 distinct commits' signatures (the replay and VERIFY group size) */
    enum { BN = 64 };
    static uint8_t bm[BN][52], bs[BN][64];
    const uint8_t *bmp[BN], *bsp[BN];
    size_t bl[BN];
    bool bok[BN];
    for (int i = 0; i < BN; i++) {
        memset(bm[i], 0, 52);
        bm[i][0] = (uint8_t)i, bm[i][1] = 0x5a;
        imdb_ed25519_sign(bs[i], ea, ep, epk, bm[i], 52);
        bmp[i] = bm[i], bsp[i] = bs[i], bl[i] = 52;
    }
    int br = 20, bgood = 0;
    imdb_ed25519_set_fe4(false);
    t0 = now();
    for (int r = 0; r < br; r++) bgood += imdb_ed25519_verify_batch(BN, bsp, epk, bmp, bl, bok);
    double tbs = (now() - t0) / (br * BN) * 1e6;
    imdb_ed25519_set_fe4(true);
    t0 = now();
    for (int r = 0; r < br; r++) bgood += imdb_ed25519_verify_batch(BN, bsp, epk, bmp, bl, bok);
    double tb = (now() - t0) / (br * BN) * 1e6;
    printf("  ed25519 batch   scalar field %6.1f us per signature, four-way field %6.1f us\n", tbs, tb);
    br *= 2;
    printf("  ed25519 batch   %6.1f us per signature in groups of %d (%.1fx the single fast check; %d/%d groups valid)\n",
           tb, BN, ts[3] / tb, bgood, br);
}

static void schema(imdb_schema *s)
{
    memset(s, 0, sizeof *s);
    strcpy(s->name, "txns");
    s->ncols = 4;
    strcpy(s->cols[0].name, "id");
    s->cols[0].type = IMDB_T_INT64;
    s->cols[0].flags = IMDB_COL_PK;
    strcpy(s->cols[1].name, "user_id");
    s->cols[1].type = IMDB_T_INT64;
    s->cols[1].flags = IMDB_COL_SUBJECT;
    strcpy(s->cols[2].name, "amount");
    s->cols[2].type = IMDB_T_DECIMAL;
    s->cols[2].precision = 12;
    s->cols[2].scale = 2;
    strcpy(s->cols[3].name, "memo");
    s->cols[3].type = IMDB_T_TEXT;
    s->pk = 0;
    s->subject = 1;
}

static int sqlq(imdb_session *ss, const char *q, imdb_result *r)
{
    imdb_err e = {0};
    int rc = imdb_exec_one(ss, q, strlen(q), NULL, 0, r, &e);
    if (rc) fprintf(stderr, "bench: %s: %s\n", q, e.msg);
    return rc;
}

static void engine(const char *base, uint64_t rows)
{
    char p[512], r[512], s[512];
    snprintf(p, sizeof p, "%s/bench-primary", base);
    snprintf(r, sizeof r, "%s/bench-replica", base);
    snprintf(s, sizeof s, "%s/bench-stream", base);
    char cmd[2048];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s' '%s'", p, r, s);
    if (system(cmd) != 0) return;
    imdb_err e = {0};
    if (imdb_init(p, false, NULL, &e) || imdb_init(r, true, p, &e)) {
        fprintf(stderr, "init: %s\n", e.msg);
        return;
    }
    imdb_open_opts o = {.sync = 0};
    imdb_db *db;
    if (imdb_open(p, &o, &db, &e)) return;
    imdb_schema sc;
    schema(&sc);
    imdb_begin(db, &e);
    imdb_create_table(db, &sc, &e);
    imdb_commit(db, &e);
    imdb_table *t = imdb_table_by_name(db, "txns");

    /* bulk load: one transaction per 50k rows (digests computed in parallel) */
    double t0 = now();
    imdb_value v[4] = {{.type = IMDB_T_INT64}, {.type = IMDB_T_INT64}, {.type = IMDB_T_DECIMAL, .scale = 2},
                       {.type = IMDB_T_TEXT, .s = (const uint8_t *)"card payment", .len = 12}};
    for (uint64_t i = 0; i < rows; i++) {
        if (i % 50000 == 0) imdb_begin(db, &e);
        v[0].i = (int64_t)i;
        v[1].i = (int64_t)(i % 10000);
        v[2].i = (int64_t)(i * 37 % 100000);
        if (imdb_insert(db, t, v, &e)) {
            fprintf(stderr, "insert: %s\n", e.msg);
            return;
        }
        if (i % 50000 == 49999 || i + 1 == rows) imdb_commit(db, &e);
    }
    double dt = now() - t0;
    printf("  bulk insert     %8.0f rows/s   (%llu rows, LtHash digest included, parallel)\n", (double)rows / dt,
           (unsigned long long)rows);

    t0 = now();
    int small = 2000;
    for (int i = 0; i < small; i++) {
        imdb_begin(db, &e);
        v[0].i = (int64_t)(rows + (uint64_t)i);
        imdb_insert(db, t, v, &e);
        imdb_commit(db, &e);
    }
    dt = now() - t0;
    printf("  single-row txn  %8.1f us/commit (sync=0, so no fdatasync: not durable latency; chain hash, Ed25519 signature,\n"
           "                                   digest and the DURABLE watermark write included)\n", dt / small * 1e6);

    t0 = now();
    if (imdb_checkpoint(db, &e)) fprintf(stderr, "checkpoint: %s\n", e.msg);
    dt = now() - t0;
    printf("  checkpoint      %8.2f s        (segments + manifest for %llu rows)\n", dt, (unsigned long long)t->nver);

    imdb_session ss;
    imdb_session_init(&ss, db);
    imdb_result res;
    t0 = now();
    int lookups = 20000;
    for (int i = 0; i < lookups; i++) {
        imdb_value key = {.type = IMDB_T_INT64, .i = (int64_t)((uint64_t)i * 7919 % rows)};
        g_sink += imdb_lookup_pk(db, t, &key, db->seq);
    }
    dt = now() - t0;
    printf("  pk lookup       %8.2f us        (engine API)\n", dt / lookups * 1e6);

    const char *queries[] = {
        "SELECT COUNT(*), SUM(amount) FROM txns WHERE user_id = 42",
        "SELECT COUNT(*), SUM(amount) FROM txns WHERE amount BETWEEN 100.00 AND 500.00",
    };
    for (int qi = 0; qi < 2; qi++) {
        for (int path = IMDB_PATH_SCAN; path <= IMDB_PATH_STORE; path++) {
            if (qi == 0 && path == IMDB_PATH_STORE) continue;
            ss.access_path = qi == 0 && path == IMDB_PATH_SCAN ? IMDB_PATH_INDEX : path;
            int reps = 0;
            t0 = now();
            do {
                if (sqlq(&ss, queries[qi], &res)) return;
                imdb_result_free(&res);
                reps++;
            } while (now() - t0 < 1.0);
            dt = (now() - t0) / reps;
            ss.access_path = qi == 0 && path == IMDB_PATH_SCAN ? IMDB_PATH_INDEX : path;
            printf("  %-16s %8.2f ms/query  %s%s\n", qi == 0 ? "user query" : "range aggregate", dt * 1e3,
                   ss.access_path == IMDB_PATH_INDEX ? "index path" : ss.access_path == IMDB_PATH_SCAN ? "SIMD scan" : "store (row at a time)",
                   qi == 1 ? "" : "");
            if (qi == 1) printf("                   = %8.0f Mrow/s\n", (double)t->nver / dt / 1e6);
        }
    }
    ss.access_path = IMDB_PATH_AUTO;

    imdb_verify_report vr;
    t0 = now();
    if (imdb_verify(db, &vr, &e)) fprintf(stderr, "verify: %s\n", e.msg);
    dt = now() - t0;
    printf("  VERIFY          %8.2f s        (read %.2f, parallel %.2f, ordered %.2f, engine %.2f, lake %.2f; %u threads)\n", dt, vr.t_read,
           vr.t_par, vr.t_log, vr.t_state, vr.t_lake, imdb_pool_threads());
    imdb_session_close(&ss);
    imdb_close(db);

    t0 = now();
    int fd = open(s, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    imdb_ship(p, 0, fd, false, &e);
    close(fd);
    imdb_db *rep;
    if (imdb_open(r, &o, &rep, &e)) return;
    fd = open(s, O_RDONLY);
    uint64_t applied;
    double t1 = now();
    if (imdb_apply_stream(rep, fd, &applied, &e)) fprintf(stderr, "apply: %s\n", e.msg);
    dt = now() - t1;
    close(fd);
    printf("  replica apply   %8.0f rows/s   (%llu commits, every check incl. lake rebuild + state recompute)\n",
           (double)rows / dt, (unsigned long long)applied);
    imdb_close(rep);
    /* open from the lake snapshot (the default) against replaying the whole log */
    t0 = now();
    if (imdb_open(p, &o, &db, &e)) return;
    dt = now() - t0;
    printf("  reopen          %8.2f s        (from the lake snapshot at commit %llu, tail replayed)\n", dt,
           (unsigned long long)db->snapshot_seq);
    imdb_close(db);
    imdb_open_opts full = o;
    full.full_replay = true;
    t0 = now();
    if (imdb_open(p, &full, &db, &e)) return;
    dt = now() - t0;
    printf("  reopen (full)   %8.2f s        (every commit replayed and re-verified)\n", dt);
    imdb_close(db);
    const char *keep = getenv("IMDB_BENCH_KEEP"); /* keep the databases, e.g. to profile an open */
    if (keep && strcmp(keep, "1") == 0) {
        printf("  kept            %s, %s\n", p, r);
        return;
    }
    snprintf(cmd, sizeof cmd, "rm -rf '%s' '%s' '%s'", p, r, s);
    if (system(cmd) != 0) return;
}

int main(int argc, char **argv)
{
    const imdb_cpu *c = imdb_cpu_get();
    printf("imagedb bench  (sse4.2=%d avx2=%d%s)\n", c->sse42, c->avx2, c->forced_scalar ? ", IMDB_NO_SIMD" : "");
    /* clocks vary with the governor: report them, numbers are only comparable at similar ones */
    FILE *gov = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r"), *cur = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    char gb[32] = "?";
    unsigned long khz = 0;
    if (gov && fscanf(gov, "%31s", gb) != 1) gb[0] = 0;
    if (cur && fscanf(cur, "%lu", &khz) != 1) khz = 0;
    if (gov) fclose(gov);
    if (cur) fclose(cur);
    printf("cpu0 governor %s, %lu MHz now\n", gb, khz / 1000);
    printf("kernels:\n");
    kernels();
    uint64_t rows = argc > 1 ? strtoull(argv[1], NULL, 10) : 200000;
    const char *base = getenv("IMDB_TEST_TMP");
    printf("engine (%llu rows):\n", (unsigned long long)rows);
    engine(base ? base : "/tmp", rows);
    return 0;
}
