/* Replica acknowledgements (repl.h, deferred.md R2): the record, the allowlist, what ship accepts
 * and records, the primary's view and the synchronous wait, the cleanup claim, and acknowledgement
 * points (each one names a commit already durable on the replica). */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../../src/cpu.h"
#include "../../src/fsio.h"
#include "../../src/repl.h"
#include "../../src/sql.h"
#include "../../src/writer.h"
#include "thelp.h"

/* the shipping session these tests receive in (ship draws a random one) */
static const uint8_t kNonce[IMDB_NONCE_LEN] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};

static void key_of(imdb_signer *s, uint8_t b)
{
    uint8_t seed[IMDB_SEED_LEN];
    memset(seed, b, sizeof seed);
    imdb_signer_init(s, seed);
}

static void make_ack(imdb_ack *a, const imdb_db *db, const imdb_signer *k, uint64_t seq, const uint8_t head[32])
{
    memset(a, 0, sizeof *a);
    memcpy(a->db_id, db->db_id, 16);
    memcpy(a->replica, k->pk, IMDB_PUBKEY_LEN);
    memcpy(a->nonce, kNonce, IMDB_NONCE_LEN);
    a->epoch = imdb_writer_epoch_at(db, seq);
    a->seq = seq;
    a->cleanup = seq;
    memcpy(a->head, head, 32);
}

/* replicas/NAME.ack as ship writes it: the record, when it was received, a CRC */
static void put_ack_file(const char *p, const char *name, const uint8_t raw[IMDB_ACK_LEN], int64_t received_ms)
{
    uint8_t rec[IMDB_ACK_LEN + 12];
    memcpy(rec, raw, IMDB_ACK_LEN);
    imdb_le64(rec + IMDB_ACK_LEN, (uint64_t)received_ms);
    imdb_le32(rec + IMDB_ACK_LEN + 8, imdb_kern()->crc32c(0, rec, IMDB_ACK_LEN + 8));
    char f[700];
    snprintf(f, sizeof f, "%s/replicas/%s.ack", p, name);
    spit(f, rec, sizeof rec);
}

/* the primary's own history, as ship's window would give it */
static int hash_from_db(void *ctx, uint64_t seq, uint8_t h[32])
{
    imdb_db *db = ctx;
    if (seq > db->seq) return 0;
    if (seq == 0) {
        imdb_genesis_hash(db->db_id, h);
        return 1;
    }
    imdb_err e = {0};
    const imdb_commit_info *ci = imdb_ci_at(db, seq, &e);
    if (!ci) return -1;
    memcpy(h, ci->hash, 32);
    return 1;
}

static int hash_unknown(void *ctx, uint64_t seq, uint8_t h[32])
{
    (void)ctx, (void)seq, (void)h;
    return -1;
}

static int receive(imdb_db *db, const imdb_ack *a, const imdb_signer *k, imdb_hash_at_fn fn)
{
    uint8_t raw[IMDB_ACK_LEN];
    imdb_ack_sign(a, k, raw);
    imdb_allow *allow = NULL;
    size_t n = 0;
    imdb_err_clear(E);
    int rc = imdb_ack_receive(db->dirfd, db->db_id, kNonce, &allow, &n, raw, fn, db, NULL, E);
    imdb_free(allow);
    return rc;
}

static imdb_replica_status *status_of(imdb_db *db, size_t *n)
{
    imdb_replica_status *v = NULL;
    imdb_err_clear(E);
    return imdb_replicas_status(db, &v, n, E) ? NULL : v;
}

static bool exists_in(const char *dir, const char *sub, const char *name)
{
    char p[700];
    snprintf(p, sizeof p, "%s/%s/%s", dir, sub, name);
    struct stat st;
    return stat(p, &st) == 0;
}

static void t_repl_ack_record(void)
{
    imdb_signer k;
    key_of(&k, 7);
    imdb_ack a;
    memset(&a, 0, sizeof a);
    memset(a.db_id, 1, 16);
    memcpy(a.replica, k.pk, IMDB_PUBKEY_LEN);
    a.seq = 12;
    a.cleanup = 10;
    a.epoch = 3;
    memcpy(a.nonce, kNonce, IMDB_NONCE_LEN);
    memset(a.head, 3, 32);
    uint8_t raw[IMDB_ACK_LEN];
    imdb_ack_sign(&a, &k, raw);
    imdb_ack b;
    OK(imdb_ack_open(raw, &b, E));
    CHECK(b.seq == 12 && b.cleanup == 10 && b.epoch == 3 && memcmp(b.nonce, kNonce, IMDB_NONCE_LEN) == 0 &&
          memcmp(b.head, a.head, 32) == 0 && memcmp(b.replica, k.pk, 32) == 0 && memcmp(b.db_id, a.db_id, 16) == 0);
    for (size_t i = 0; i < IMDB_ACK_LEN; i++) { /* every byte is covered: magic, fields, padding, key, signature */
        uint8_t t[IMDB_ACK_LEN];
        memcpy(t, raw, sizeof t);
        t[i] ^= 0x40;
        CHECK(imdb_ack_open(t, &b, E) != IMDB_OK);
    }
    a.cleanup = 13; /* signed, but a cleanup claim past its own commit */
    imdb_ack_sign(&a, &k, raw);
    CHECK(imdb_ack_open(raw, &b, E) == IMDB_ERR_CORRUPT);
    imdb_signer_wipe(&k);
}

static void t_repl_allowlist(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_signer a, b, c;
    key_of(&a, 1);
    key_of(&b, 2);
    key_of(&c, 3);
    const char *bad[] = {"", "R1", "r/1", "r.1", "a23456789012345678901234567890123"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) CHECK(imdb_replica_add(p, bad[i], a.pk, false, E) == IMDB_ERR_INVALID);
    OK(imdb_replica_add(p, "r2", b.pk, false, E));
    OK(imdb_replica_add(p, "r1", a.pk, false, E));
    CHECK(imdb_replica_add(p, "r1", c.pk, false, E) == IMDB_ERR_CONSTRAINT); /* the name is taken */
    CHECK(imdb_replica_add(p, "r3", a.pk, false, E) == IMDB_ERR_CONSTRAINT); /* the key is r1's */
    CHECK(imdb_replica_add(p, "r2", a.pk, true, E) == IMDB_ERR_CONSTRAINT);  /* nor can r2 take it */
    CHECK(imdb_replica_add(p, "r9", c.pk, true, E) == IMDB_ERR_NOTFOUND);    /* nothing to replace */
    imdb_err_clear(E);
    CHECK(imdb_replica_add(p, "r1", a.pk, true, E) == IMDB_ERR_CONSTRAINT && strstr(g_e.msg, "needs a new key"));
    int dfd = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    imdb_allow *l;
    size_t n;
    OK(imdb_allowlist_load(dfd, &l, &n, E));
    CHECK(n == 2 && strcmp(l[0].name, "r1") == 0 && strcmp(l[1].name, "r2") == 0 && memcmp(l[0].pub, a.pk, 32) == 0 &&
          memcmp(l[1].pub, b.pk, 32) == 0);
    imdb_free(l);
    char f[700];
    snprintf(f, sizeof f, "%s/replicas/r2.pub", p);
    spit(f, (const uint8_t *)"not a key\n", 10); /* refused, never skipped: a damaged allowlist is an error */
    CHECK(imdb_allowlist_load(dfd, &l, &n, E) == IMDB_ERR_CORRUPT);
    close(dfd);
}

static void t_repl_receive(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    OK(ins1(db, 2, 7, 100, "b"));
    imdb_signer a, b, c;
    key_of(&a, 1);
    key_of(&b, 2);
    key_of(&c, 3);
    OK(imdb_replica_add(p, "r1", a.pk, false, E));
    imdb_ack k;
    make_ack(&k, db, &a, db->seq, db->head);
    OK(receive(db, &k, &a, hash_from_db));
    size_t n;
    imdb_replica_status *v = status_of(db, &n);
    CHECK(v && n == 1 && v[0].acked && v[0].ack.seq == db->seq && v[0].state == IMDB_REPL_SAME_HISTORY && !v[0].incident);
    imdb_free(v);
    /* refused, and nothing recorded: a key no one allowlisted, another database, an unseen commit */
    make_ack(&k, db, &b, db->seq, db->head);
    CHECK(receive(db, &k, &b, hash_from_db) == IMDB_ERR_AUTH);
    make_ack(&k, db, &a, db->seq, db->head);
    k.db_id[0] ^= 1;
    CHECK(receive(db, &k, &a, hash_from_db) == IMDB_ERR_VERIFY && strstr(g_e.msg, "another database"));
    make_ack(&k, db, &a, 1, db->head);
    CHECK(receive(db, &k, &a, hash_unknown) == IMDB_ERR_VERIFY && strstr(g_e.msg, "has not seen"));
    CHECK(!exists_in(p, "replicas", "r1.diverged"));
    /* another history at commit 2: recorded durably, and the replica refused from then on */
    uint8_t other[32];
    memset(other, 0x5a, sizeof other);
    make_ack(&k, db, &a, 2, other);
    CHECK(receive(db, &k, &a, hash_from_db) == IMDB_ERR_VERIFY && strstr(g_e.msg, "different history"));
    CHECK(exists_in(p, "replicas", "r1.diverged"));
    make_ack(&k, db, &a, db->seq, db->head);
    CHECK(receive(db, &k, &a, hash_from_db) == IMDB_ERR_STATE && strstr(g_e.msg, "diverged"));
    v = status_of(db, &n);
    CHECK(v && n == 1 && v[0].incident && v[0].state == IMDB_REPL_DIVERGED && v[0].refused.seq == 2);
    imdb_free(v);
    /* the operator re-initialised it: a new key, a clean slate */
    OK(imdb_replica_add(p, "r1", c.pk, true, E));
    CHECK(!exists_in(p, "replicas", "r1.diverged") && !exists_in(p, "replicas", "r1.ack"));
    v = status_of(db, &n);
    CHECK(v && n == 1 && !v[0].acked && v[0].state == IMDB_REPL_NONE);
    imdb_free(v);
    make_ack(&k, db, &a, db->seq, db->head); /* the old key is gone with it */
    CHECK(receive(db, &k, &a, hash_from_db) == IMDB_ERR_AUTH);
    /* a replica holding commits beyond this log (lost here in a --nosync crash, or another primary) */
    make_ack(&k, db, &c, db->seq + 3, other);
    CHECK(receive(db, &k, &c, hash_from_db) == IMDB_ERR_VERIFY && strstr(g_e.msg, "beyond this primary"));
    CHECK(exists_in(p, "replicas", "r1.diverged"));
    /* SHOW REPLICAS reads an ahead acknowledgement as such (written as ship would have, before a rollback) */
    OK(imdb_replica_add(p, "r1", a.pk, true, E));
    make_ack(&k, db, &a, db->seq + 3, other);
    uint8_t raw[IMDB_ACK_LEN];
    imdb_ack_sign(&k, &a, raw);
    put_ack_file(p, "r1", raw, 1000);
    v = status_of(db, &n);
    CHECK(v && n == 1 && v[0].acked && v[0].state == IMDB_REPL_AHEAD && v[0].received_ms == 1000 && v[0].age_ms > 0);
    imdb_free(v);
    raw[100] ^= 1; /* a damaged record (its CRC recomputed) reads as no acknowledgement: its signature */
    put_ack_file(p, "r1", raw, 1000);
    v = status_of(db, &n);
    CHECK(v && n == 1 && !v[0].acked && v[0].state == IMDB_REPL_NONE);
    imdb_free(v);
    raw[100] ^= 1; /* a torn one: its CRC */
    put_ack_file(p, "r1", raw, 1000);
    char f[700];
    snprintf(f, sizeof f, "%s/replicas/r1.ack", p);
    size_t fl;
    uint8_t *fb = slurp(f, &fl);
    CHECK(fb && fl == IMDB_ACK_LEN + 12);
    if (fb) {
        fb[IMDB_ACK_LEN + 2] ^= 1;
        spit(f, fb, fl);
        free(fb);
    }
    v = status_of(db, &n);
    CHECK(v && n == 1 && !v[0].acked);
    imdb_free(v);
    imdb_close(db);
}

typedef struct late_ack {
    imdb_db *db;
    const imdb_signer *k;
    uint64_t seq;
    uint8_t head[32];
    int rc;
} late_ack;

static int hash_fixed(void *ctx, uint64_t seq, uint8_t h[32])
{
    const late_ack *l = ctx;
    if (seq != l->seq) return -1;
    memcpy(h, l->head, 32);
    return 1;
}

static void *ack_later(void *arg)
{
    late_ack *l = arg;
    struct timespec ts = {0, 50 * 1000 * 1000};
    nanosleep(&ts, NULL);
    imdb_ack a;
    make_ack(&a, l->db, l->k, l->seq, l->head);
    uint8_t raw[IMDB_ACK_LEN];
    imdb_ack_sign(&a, l->k, raw);
    imdb_allow *allow = NULL;
    size_t n = 0;
    imdb_err e = {0};
    l->rc = imdb_ack_receive(l->db->dirfd, l->db->db_id, kNonce, &allow, &n, raw, hash_fixed, l, NULL, &e);
    imdb_free(allow);
    return NULL;
}

static int64_t ms_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void t_repl_wait(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    imdb_signer a, b;
    key_of(&a, 1);
    key_of(&b, 2);
    uint32_t got = 9;
    OK(imdb_replicas_wait(db, db->seq, 1, 50, &got, E)); /* no replica allowlisted: nothing to wait for */
    CHECK(got == 0);
    OK(imdb_replica_add(p, "r1", a.pk, false, E));
    OK(imdb_replica_add(p, "r2", b.pk, false, E));
    imdb_ack k;
    make_ack(&k, db, &a, db->seq, db->head);
    OK(receive(db, &k, &a, hash_from_db));
    int64_t t0 = ms_now();
    OK(imdb_replicas_wait(db, db->seq, 1, 5000, &got, E));
    CHECK(got == 1 && ms_now() - t0 < 1000); /* already there: no waiting */
    t0 = ms_now();
    OK(imdb_replicas_wait(db, db->seq, 2, 200, &got, E));
    CHECK(got == 1 && ms_now() - t0 >= 150); /* r2 never answered: the whole timeout */
    /* a newer commit: r1's acknowledgement no longer covers it, until one arrives while waiting */
    OK(ins1(db, 2, 7, 100, "b"));
    OK(imdb_replicas_wait(db, db->seq, 1, 100, &got, E));
    CHECK(got == 0);
    late_ack l = {.db = db, .k = &a, .seq = db->seq, .rc = -1};
    memcpy(l.head, db->head, 32);
    pthread_t th;
    CHECK(pthread_create(&th, NULL, ack_later, &l) == 0);
    t0 = ms_now();
    int rc = imdb_replicas_wait(db, db->seq, 1, 5000, &got, E);
    pthread_join(th, NULL);
    CHECK(rc == IMDB_OK && l.rc == IMDB_OK && got == 1 && ms_now() - t0 < 2000);
    /* a replica recorded as diverged never counts, and the wait does not sit out its timeout for it */
    uint8_t other[32];
    memset(other, 0x5a, sizeof other);
    make_ack(&k, db, &b, 1, other);
    CHECK(receive(db, &k, &b, hash_from_db) == IMDB_ERR_VERIFY);
    t0 = ms_now();
    OK(imdb_replicas_wait(db, db->seq, 2, 5000, &got, E));
    CHECK(got == 1 && ms_now() - t0 < 2000);
    imdb_close(db);
}

static int run_sql(imdb_session *s, const char *sql, imdb_result *r)
{
    imdb_err_clear(E);
    int rc = imdb_exec_one(s, sql, strlen(sql), NULL, 0, r, E);
    return rc;
}

static bool cell_is(const imdb_result *r, uint64_t row, uint16_t col, const char *s)
{
    const imdb_cell *c = &r->cells[row * r->ncols + col];
    return c->v.type == IMDB_T_TEXT && c->v.len == strlen(s) && memcmp(c->v.s, s, c->v.len) == 0;
}

static int64_t cell_int(const imdb_result *r, uint64_t row, uint16_t col) { return r->cells[row * r->ncols + col].v.i; }

static void t_repl_sql(void)
{
    const char *p = test_tmpdir();
    char r[600];
    snprintf(r, sizeof r, "%s/r", p);
    char pp[600];
    snprintf(pp, sizeof pp, "%s/p", p);
    OK(imdb_init(pp, false, NULL, E));
    OK(imdb_init(r, true, pp, E));
    imdb_db *db = open_db(pp);
    CHECK(db);
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result res;
    const char *bad[] = {"SET sync_replicas = 65", "SET sync_replicas = x", "SET sync_timeout_ms = 0",
                         "SET sync_timeout_ms = 3600001"};
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++)
        CHECK(run_sql(&s, bad[i], &res) == IMDB_ERR_INVALID && strstr(g_e.msg, "sync_"));
    CHECK(run_sql(&s, "SET sync_replicas = -1", &res) == IMDB_ERR_SYNTAX); /* a setting value is never signed */
    OK(run_sql(&s, "SHOW REPLICATION", &res));
    CHECK(res.nrows == 0 && strstr(res.status, "no commit in this session"));
    imdb_result_free(&res);
    OK(run_sql(&s, "CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)", &res));
    imdb_result_free(&res);
    OK(run_sql(&s, "SHOW REPLICATION", &res)); /* sync_replicas = 0: nothing waited for */
    CHECK(res.nrows == 1 && res.ncols == 5 && cell_int(&res, 0, 0) == (int64_t)db->seq && cell_is(&res, 0, 4, "local only"));
    imdb_result_free(&res);
    imdb_signer k;
    bool created;
    OK(imdb_replica_key(r, false, &k, &created, E)); /* init-replica made it */
    CHECK(!created);
    OK(imdb_replica_add(pp, "r1", k.pk, false, E));
    imdb_ack a;
    make_ack(&a, db, &k, db->seq, db->head);
    OK(receive(db, &a, &k, hash_from_db));
    OK(run_sql(&s, "SHOW REPLICAS", &res));
    CHECK(res.nrows == 1 && res.ncols == 10);
    imdb_result_free(&res);
    OK(run_sql(&s, "SET sync_replicas = 1", &res));
    imdb_result_free(&res);
    OK(run_sql(&s, "SET sync_timeout_ms = 100", &res));
    imdb_result_free(&res);
    db->warning[0] = 0;
    OK(run_sql(&s, "INSERT INTO t VALUES (1, 1)", &res)); /* durable here: no follower, so an outcome, not an error */
    CHECK(strstr(res.status, "INSERT 1; commit") && strstr(res.status, "replication unknown: acknowledged by 0 of 1"));
    imdb_result_free(&res);
    CHECK(strstr(db->warning, "only 0 of 1 replicas") != NULL);
    OK(run_sql(&s, "SHOW REPLICATION", &res));
    CHECK(res.nrows == 1 && cell_int(&res, 0, 0) == (int64_t)db->seq && cell_int(&res, 0, 1) == 1 &&
          cell_int(&res, 0, 2) == 0 && cell_int(&res, 0, 3) >= 90 && cell_is(&res, 0, 4, "unknown"));
    imdb_result_free(&res);
    db->warning[0] = 0;
    OK(run_sql(&s, "SELECT * FROM t", &res)); /* no commit, no wait */
    imdb_result_free(&res);
    CHECK(db->warning[0] == 0);
    imdb_session_close(&s);
    imdb_close(db);
    db = open_db(r);
    CHECK(db);
    imdb_session_init(&s, db);
    CHECK(run_sql(&s, "SET sync_replicas = 1", &res) == IMDB_ERR_STATE); /* a primary's setting */
    imdb_session_close(&s);
    imdb_close(db);
    imdb_signer_wipe(&k);
}

/* acknowledgement points: what each one may claim */
typedef struct point {
    uint64_t seq, cleanup;
    bool durable;
} point;

typedef struct points {
    point p[64];
    int n;
} points;

static int record_point(void *ctx, imdb_db *db)
{
    points *ps = ctx;
    if (ps->n < 64) ps->p[ps->n++] = (point){db->seq, imdb_cleanup_seq(db), db->unsynced_from == 0};
    return 0;
}

/* fails every removal of a lake object: GC cannot finish */
static long no_object_unlink(imdb_io_call *c, void *ctx)
{
    (void)ctx;
    if (c->op == IMDB_IO_UNLINK && c->name && strlen(c->name) == 68 && strcmp(c->name + 64, ".seg") == 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int apply_points(imdb_db *db, const char *stream, points *ps)
{
    imdb_apply_opts ao = {.applied = record_point, .ctx = ps, .every = 1};
    uint64_t applied;
    int fd = open(stream, O_RDONLY | O_CLOEXEC);
    imdb_err_clear(E);
    int rc = imdb_apply_stream_ex(db, fd, &applied, &ao, E);
    close(fd);
    return rc;
}

static void t_repl_points_cleanup(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r1[600], r2[600], sa[600], sb[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(r1, sizeof r1, "%s/r1", tmp);
    snprintf(r2, sizeof r2, "%s/r2", tmp);
    snprintf(sa, sizeof sa, "%s/stream-a", tmp);
    snprintf(sb, sizeof sb, "%s/stream-b", tmp);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "secret-42"));
    OK(ins1(db, 2, 7, 100, "plain-7"));
    OK(imdb_checkpoint(db, E)); /* the rows reach lake objects, here and on the replicas */
    uint64_t cp = db->seq;
    OK(ship_to_file(p, 0, sa, E));
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report rep;
    OK(imdb_erase_subject(db, &subj, &rep, E));
    uint64_t erase_seq = db->seq;
    OK(ins1(db, 3, 7, 100, "after"));
    uint64_t last = db->seq;
    imdb_close(db);
    OK(ship_to_file(p, cp, sb, E));
    imdb_open_opts o = {.sync = 0};
    /* a --nosync replica, a point after every commit: each names a durable commit, and the cleanup
     * claim follows every commit, the ERASE included */
    OK(imdb_init(r1, true, p, E));
    OK(imdb_open(r1, &o, &db, E));
    points ps = {.n = 0};
    OK(apply_points(db, sa, &ps));
    CHECK(tree_contains(r1, "secret-42")); /* the replica holds it, in its log and its lake */
    OK(apply_points(db, sb, &ps));
    CHECK(ps.n == (int)last);
    for (int i = 0; i < ps.n; i++) CHECK(ps.p[i].durable && ps.p[i].seq == (uint64_t)i + 1 && ps.p[i].cleanup == ps.p[i].seq);
    imdb_close(db);
    CHECK(!tree_contains(r1, "secret-42"));
    /* another replica, whose old objects cannot be removed: from the ERASE on, the claim stays at the
     * commit before it (the files still hold the subject's bytes), until a writable open finishes GC */
    OK(imdb_init(r2, true, p, E));
    OK(imdb_open(r2, &o, &db, E));
    ps.n = 0;
    OK(apply_points(db, sa, &ps));
    imdb_io_hooks h = {.before = no_object_unlink};
    imdb_io_set_hooks(&h);
    int rc = apply_points(db, sb, &ps);
    imdb_io_set_hooks(NULL);
    OK_RC(rc);
    CHECK(db->gc_pending && ps.n == (int)last);
    for (int i = 0; i < ps.n; i++)
        CHECK(ps.p[i].durable && ps.p[i].cleanup == (ps.p[i].seq < erase_seq ? ps.p[i].seq : erase_seq - 1));
    CHECK(tree_contains(r2, "secret-42")); /* why the claim held back */
    imdb_close(db);
    OK(imdb_open(r2, &o, &db, E));
    CHECK(!db->gc_pending && imdb_cleanup_seq(db) == last);
    imdb_close(db);
    CHECK(!tree_contains(r2, "secret-42"));
}

/* every 64 commits while the stream has more, and at its end */
static void t_repl_points_batch(void)
{
    const char *tmp = test_tmpdir();
    char p[600], r[600], st[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    snprintf(st, sizeof st, "%s/stream", tmp);
    OK(imdb_init(p, false, NULL, E));
    imdb_open_opts o = {.sync = 0};
    imdb_db *db;
    OK(imdb_open(p, &o, &db, E));
    OK(make_table(db, E));
    for (int64_t i = 1; i < 130; i++) OK(ins1(db, i, 7, 100, "x")); /* commits 1 .. 130 */
    imdb_close(db);
    OK(imdb_init(r, true, p, E));
    OK(ship_to_file(p, 0, st, E));
    OK(imdb_open(r, &o, &db, E));
    points ps = {.n = 0};
    imdb_apply_opts ao = {.applied = record_point, .ctx = &ps};
    uint64_t applied;
    int fd = open(st, O_RDONLY | O_CLOEXEC); /* a file: always more to read until its end */
    OK(imdb_apply_stream_ex(db, fd, &applied, &ao, E));
    close(fd);
    CHECK(applied == 130 && ps.n == 3 && ps.p[0].seq == 64 && ps.p[1].seq == 128 && ps.p[2].seq == 130);
    for (int i = 0; i < ps.n; i++) CHECK(ps.p[i].durable);
    imdb_close(db);
}

/* B3 (review 2026-10-22): an acknowledgement counts only in the session whose challenge it signs;
 * for one key (one incarnation) the commit never goes back, so a replica restored from an older
 * copy without re-enrolment is caught; the epoch must be the primary's at that commit. */
static void t_repl_incarnation(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    OK(ins1(db, 2, 7, 100, "b"));
    imdb_signer a, c;
    key_of(&a, 1);
    key_of(&c, 3);
    OK(imdb_replica_add(p, "r1", a.pk, false, E));
    imdb_ack k;
    make_ack(&k, db, &a, db->seq, db->head);
    k.nonce[0] ^= 1; /* signed for another session: refused, nothing recorded */
    CHECK(receive(db, &k, &a, hash_from_db) == IMDB_ERR_VERIFY && strstr(g_e.msg, "another shipping session"));
    CHECK(!exists_in(p, "replicas", "r1.ack") && !exists_in(p, "replicas", "r1.diverged"));
    uint64_t tip = db->seq;
    uint8_t below[32];
    const imdb_commit_info *ci = imdb_ci_at(db, tip - 1, E);
    CHECK(ci);
    if (!ci) return;
    memcpy(below, ci->hash, 32);
    make_ack(&k, db, &a, tip, db->head);
    OK(receive(db, &k, &a, hash_from_db));
    make_ack(&k, db, &a, tip - 1, below); /* the same key one commit lower: it lost an acknowledged commit */
    CHECK(receive(db, &k, &a, hash_from_db) == IMDB_ERR_VERIFY && strstr(g_e.msg, "lost acknowledged"));
    size_t n;
    imdb_replica_status *v = status_of(db, &n);
    CHECK(v && n == 1 && v[0].incident && v[0].why == IMDB_REFUSED_BACK && v[0].earlier == tip &&
          v[0].refused.seq == tip - 1 && v[0].state == IMDB_REPL_DIVERGED);
    imdb_free(v);
    make_ack(&k, db, &a, tip, db->head); /* refused from then on, at the tip too */
    CHECK(receive(db, &k, &a, hash_from_db) == IMDB_ERR_STATE && strstr(g_e.msg, "recorded incident"));
    OK(imdb_replica_add(p, "r1", c.pk, true, E)); /* re-enrolled: a new incarnation starts where it is */
    make_ack(&k, db, &c, tip - 1, below);
    OK(receive(db, &k, &c, hash_from_db));
    /* only what the same key acknowledged counts: a record another key left is no evidence */
    uint8_t raw[IMDB_ACK_LEN];
    make_ack(&k, db, &a, tip, db->head);
    imdb_ack_sign(&k, &a, raw);
    put_ack_file(p, "r1", raw, 1000);
    make_ack(&k, db, &c, tip - 1, below);
    OK(receive(db, &k, &c, hash_from_db));
    /* an epoch the primary's history does not have at that commit: not the same history, never counted */
    make_ack(&k, db, &c, tip, db->head);
    k.epoch = 7;
    imdb_ack_sign(&k, &c, raw);
    put_ack_file(p, "r1", raw, 1000);
    v = status_of(db, &n);
    CHECK(v && n == 1 && v[0].acked && v[0].state == IMDB_REPL_DIVERGED);
    imdb_free(v);
    uint32_t got = 9;
    OK(imdb_replicas_wait(db, tip, 1, 50, &got, E));
    CHECK(got == 0);
    imdb_close(db);
    imdb_signer_wipe(&a);
    imdb_signer_wipe(&c);
}

typedef struct add_later {
    const char *p;
    const uint8_t *pub;
    int rc;
    _Atomic int done;
} add_later;

static void *add_thread(void *arg)
{
    add_later *x = arg;
    imdb_err e = {0};
    x->rc = imdb_replica_add(x->p, "r2", x->pub, false, &e);
    atomic_store(&x->done, 1);
    return NULL;
}

/* replica-add waits while a receipt holds replicas/ (LOCK_SH): no binding changes under one */
static void t_repl_admin_lock(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_signer a, b;
    key_of(&a, 1);
    key_of(&b, 2);
    OK(imdb_replica_add(p, "r1", a.pk, false, E));
    char rd[700];
    snprintf(rd, sizeof rd, "%s/replicas", p);
    int fd = open(rd, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(fd >= 0 && flock(fd, LOCK_SH) == 0);
    add_later x = {.p = p, .pub = b.pk, .rc = -1};
    atomic_init(&x.done, 0);
    pthread_t th;
    CHECK(pthread_create(&th, NULL, add_thread, &x) == 0);
    struct timespec ts = {0, 200 * 1000 * 1000};
    nanosleep(&ts, NULL);
    CHECK(atomic_load(&x.done) == 0); /* still waiting for the receipt */
    close(fd);
    pthread_join(th, NULL);
    CHECK(atomic_load(&x.done) == 1 && x.rc == IMDB_OK);
}

typedef struct first_points {
    imdb_apply_opts *ao;
    uint64_t seq_at_first;
    bool session_at_first;
    int n;
} first_points;

static int note_first(void *ctx, imdb_db *db)
{
    first_points *f = ctx;
    if (!f->n++) {
        f->seq_at_first = db->seq;
        f->session_at_first = f->ao->has_session;
    }
    return 0;
}

/* The session record (ship --acks): its nonce reaches the replica before the first point, which
 * runs before any frame (where the replica stands). A damaged one, or another database's, stops
 * the apply; a stream without one applies as before, without a session. */
static void t_repl_session_stream(void)
{
    const char *t = test_tmpdir();
    char p[600], r[600], st[700], s2[700];
    snprintf(p, sizeof p, "%s/p", t);
    snprintf(r, sizeof r, "%s/r", t);
    snprintf(st, sizeof st, "%s/stream", t);
    snprintf(s2, sizeof s2, "%s/stream2", t);
    OK(imdb_init(p, false, NULL, E));
    OK(imdb_init(r, true, p, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "a"));
    uint8_t id[16];
    memcpy(id, db->db_id, 16);
    imdb_close(db);
    OK(ship_to_file(p, 0, st, E));
    size_t n;
    uint8_t *frames = slurp(st, &n);
    CHECK(frames && n);
    if (!frames) return;
    for (int mode = 0; mode < 4; mode++) { /* 0: a session; 1: damaged; 2: another database's; 3: none */
        uint8_t sr[IMDB_SESSION_LEN], other[16];
        memcpy(other, id, 16);
        other[0] ^= 1;
        imdb_session_encode(mode == 2 ? other : id, kNonce, sr);
        if (mode == 1) sr[30] ^= 1;
        uint8_t *buf = malloc(n + sizeof sr);
        CHECK(buf);
        if (!buf) break;
        size_t len = 0;
        if (mode != 3) {
            memcpy(buf, sr, sizeof sr);
            len = sizeof sr;
        }
        memcpy(buf + len, frames, n);
        spit(s2, buf, len + n);
        free(buf);
        char rr[700];
        snprintf(rr, sizeof rr, "%s/r%d", t, mode);
        OK(imdb_init(rr, true, p, E));
        imdb_db *rep = open_db(rr);
        CHECK(rep);
        if (!rep) break;
        imdb_apply_opts ao = {.applied = note_first, .every = 1};
        first_points f = {.ao = &ao};
        ao.ctx = &f;
        uint64_t applied = 0;
        int fd = open(s2, O_RDONLY | O_CLOEXEC);
        imdb_err_clear(E);
        int rc = imdb_apply_stream_ex(rep, fd, &applied, &ao, E);
        close(fd);
        if (mode == 0)
            CHECK(rc == IMDB_OK && ao.has_session && memcmp(ao.nonce, kNonce, IMDB_NONCE_LEN) == 0 &&
                  f.session_at_first && f.seq_at_first == 0 && f.n > 1 && rep->seq == 2);
        else if (mode == 3)
            CHECK(rc == IMDB_OK && !ao.has_session && rep->seq == 2 && f.n >= 1 && f.seq_at_first > 0);
        else
            CHECK(rc != IMDB_OK && !ao.has_session && rep->seq == 0 &&
                  strstr(g_e.msg, mode == 1 ? "damaged session" : "another database"));
        imdb_close(rep);
    }
    free(frames);
}

/* SHOW ERASURE keeps the completion states apart: this directory's files (its own cleanup), each
 * replica's last report (with its age: not its state now), and the two nothing here covers. */
static void t_repl_erasure_states(void)
{
    const char *p = test_tmpdir();
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 42, 100, "secret"));
    OK(ins1(db, 2, 7, 100, "plain"));
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result res;
    OK(run_sql(&s, "ERASE SUBJECT 42", &res));
    uint64_t at = db->seq;
    char want[64];
    snprintf(want, sizeof want, "at commit %llu;", (unsigned long long)at);
    CHECK(strstr(res.status, want) != NULL);
    imdb_result_free(&res);
    imdb_signer a, b, c;
    key_of(&a, 1);
    key_of(&b, 2);
    key_of(&c, 3);
    OK(imdb_replica_add(p, "r1", a.pk, false, E));
    OK(imdb_replica_add(p, "r2", b.pk, false, E));
    OK(imdb_replica_add(p, "r3", c.pk, false, E));
    imdb_ack k;
    make_ack(&k, db, &a, at, db->head);
    k.cleanup = at - 1; /* r1 applied the ERASE, its cleanup not finished */
    OK(receive(db, &k, &a, hash_from_db));
    make_ack(&k, db, &b, at, db->head); /* r2: done; r3: never heard from */
    OK(receive(db, &k, &b, hash_from_db));
    OK(run_sql(&s, "SHOW ERASURE", &res));
    CHECK(res.nrows == 6 && res.ncols == 4);
    if (res.nrows == 6) {
        CHECK(cell_is(&res, 0, 0, "this database") && cell_is(&res, 0, 1, "complete") && cell_int(&res, 0, 2) == (int64_t)at);
        CHECK(cell_is(&res, 1, 0, "replica r1") && cell_is(&res, 1, 1, "reported pending"));
        CHECK(cell_is(&res, 2, 0, "replica r2") && cell_is(&res, 2, 1, "reported complete"));
        CHECK(cell_is(&res, 3, 0, "replica r3") && cell_is(&res, 3, 1, "unknown") && cell_int(&res, 3, 2) == -1);
        CHECK(cell_is(&res, 4, 1, "not tracked") && cell_is(&res, 5, 1, "not guaranteed"));
    }
    CHECK(strstr(res.status, "complete here; 1 of 3 replicas report it complete"));
    imdb_result_free(&res);
    OK(ins1(db, 3, 7, 100, "later")); /* through the ERASE's commit, not the current one */
    snprintf(want, sizeof want, "SHOW ERASURE AT %llu", (unsigned long long)at);
    OK(run_sql(&s, want, &res));
    CHECK(res.nrows == 6 && cell_is(&res, 2, 1, "reported complete"));
    imdb_result_free(&res);
    OK(run_sql(&s, "SHOW ERASURE", &res)); /* through the newest: r2 has not reached it */
    CHECK(res.nrows == 6 && cell_is(&res, 2, 1, "not reached"));
    imdb_result_free(&res);
    snprintf(want, sizeof want, "SHOW ERASURE AT %llu", (unsigned long long)db->seq + 1);
    CHECK(run_sql(&s, want, &res) == IMDB_ERR_INVALID && strstr(g_e.msg, "past"));
    CHECK(run_sql(&s, "SHOW ERASURE AT 0", &res) == IMDB_ERR_SYNTAX);
    imdb_session_close(&s);
    imdb_close(db);
    imdb_signer_wipe(&a);
    imdb_signer_wipe(&b);
    imdb_signer_wipe(&c);
}

const test_case repl_tests[] = {
    {"repl_ack_record", t_repl_ack_record},
    {"repl_allowlist", t_repl_allowlist},
    {"repl_receive", t_repl_receive},
    {"repl_wait", t_repl_wait},
    {"repl_sql", t_repl_sql},
    {"repl_points_cleanup", t_repl_points_cleanup},
    {"repl_points_batch", t_repl_points_batch},
    {"repl_incarnation", t_repl_incarnation},
    {"repl_admin_lock", t_repl_admin_lock},
    {"repl_session_stream", t_repl_session_stream},
    {"repl_erasure_states", t_repl_erasure_states},
};
const size_t repl_ntests = sizeof repl_tests / sizeof *repl_tests;
