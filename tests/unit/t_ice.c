/* F5c: the Iceberg v3 layer per copy (src/iceberg.c, src/icecodec.c), read with the auditor's own readers
 * (tools/audit/aice.c, linked into the suite): each codec's output read back by them; the layer's snapshots, data files
 * and deletion vectors against imagedb's own answers AS OF each snapshot; written twice the same bytes; VERIFY taking it
 * and refusing a flipped byte; an ERASE's layer holding one snapshot and none of the files of the one before. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/backup.h"

#include "../../src/db_internal.h"
#include "../../src/fsio.h"
#include "../../src/iceberg.h"
#include "../../src/icecodec.h"
#include "../../src/lake.h"
#include "../../src/sql.h"
#include "../../tools/audit/aice.h"
#include "thelp.h"

/* ---- the codecs, read back by the auditor's readers ---- */

static int dv_round(const uint64_t *pos, size_t n)
{
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_err e = {0};
    int bad = imdb_dv_blob(&b, pos, n, &e) != 0;
    uint64_t *got = NULL;
    size_t gn = 0;
    const char *why = NULL;
    if (!bad) bad = adv_read(b.p, b.len, &got, &gn, &why) != 0 || gn != n || (n && memcmp(got, pos, n * sizeof *pos));
    if (bad && why) fprintf(stderr, "    %s\n", why);
    free(got);
    imdb_buf_free(&b);
    return bad;
}

static void t_ice_roaring(void)
{
    enum { N = 70000 };
    uint64_t *p = malloc(N * sizeof *p);
    CHECK(p);
    if (!p) return;
    p[0] = 0;
    CHECK(dv_round(p, 1) == 0);
    for (size_t k = 0; k < 4096; k++) p[k] = k; /* an array container at its most */
    CHECK(dv_round(p, 4096) == 0);
    for (size_t k = 0; k < 4097; k++) p[k] = k; /* a bitset container at its least */
    CHECK(dv_round(p, 4097) == 0);
    size_t n = 0;
    for (uint64_t v = 0; v < 2 * N && n < N; v += 2) p[n++] = v; /* every other row, across keys and kinds */
    CHECK(dv_round(p, n) == 0);
    p[0] = 7, p[1] = 65535, p[2] = 65536, p[3] = (1ull << 32) + 5, p[4] = (1ull << 32) + 70000, p[5] = (1ull << 62) + 1;
    CHECK(dv_round(p, 6) == 0); /* containers' and keys' edges, a high key past 2^32 */
    test_seed(5);
    n = 0;
    for (uint64_t v = 0; v < 300000 && n < N; v++)
        if (test_rand() % 7 == 0) p[n++] = v;
    CHECK(dv_round(p, n) == 0);
    /* the writer refuses a set not ascending; the reader refuses each flipped byte of a blob (its CRC, its length or its
     * magic; a flip in the bitmap the CRC catches) */
    uint64_t un[3] = {5, 3, 9};
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_err e = {0};
    CHECK(imdb_dv_blob(&b, un, 3, &e) == IMDB_ERR_STATE);
    b.len = 0;
    uint64_t ok3[3] = {3, 5, 9};
    OK(imdb_dv_blob(&b, ok3, 3, E));
    for (size_t at = 0; at < b.len; at++) {
        b.p[at] ^= 0x01;
        uint64_t *got = NULL;
        size_t gn = 0;
        const char *why;
        CHECK(adv_read(b.p, b.len, &got, &gn, &why) != 0);
        free(got);
        b.p[at] ^= 0x01;
    }
    imdb_buf_free(&b);
    free(p);
}

static void t_ice_json(void)
{
    imdb_buf b;
    imdb_buf_init(&b);
    ij j;
    ij_begin(&j, &b);
    ij_obj(&j);
    ij_key(&j, "s");
    ij_str(&j, "a\"b\\c\n\x01\x1f end", 12);
    ij_key(&j, "min");
    ij_i64(&j, INT64_MIN);
    ij_key(&j, "max");
    ij_i64(&j, INT64_MAX);
    ij_key(&j, "a");
    ij_arr(&j);
    ij_bool(&j, true);
    ij_null(&j);
    ij_obj(&j);
    ij_end_obj(&j);
    ij_arr(&j);
    ij_end_arr(&j);
    ij_end_arr(&j);
    ij_end_obj(&j);
    aj v;
    const char *why = NULL;
    CHECK(aj_parse((const char *)b.p, b.len, &v, &why) == 0);
    const aj *s = aj_get(&v, "s"), *mn = aj_get(&v, "min"), *mx = aj_get(&v, "max"), *a = aj_get(&v, "a");
    CHECK(s && s->kind == AJ_STR && !strcmp(s->s, "a\"b\\c\n\x01\x1f end"));
    CHECK(mn && mn->kind == AJ_INT && mn->i == INT64_MIN && mx && mx->kind == AJ_INT && mx->i == INT64_MAX);
    CHECK(a && a->kind == AJ_ARR && a->n == 4 && a->v[0].kind == AJ_BOOL && a->v[1].kind == AJ_NULL && a->v[2].kind == AJ_OBJ &&
          a->v[3].kind == AJ_ARR);
    aj_free(&v);
    imdb_buf_free(&b);
}

static void t_ice_avro(void)
{
    static const int64_t vals[] = {0, 1, -1, 63, -64, 64, -65, 8191, INT32_MAX, INT32_MIN, INT64_MAX, INT64_MIN};
    imdb_buf r;
    imdb_buf_init(&r);
    for (size_t k = 0; k < sizeof vals / sizeof *vals; k++) imdb_av_long(&r, vals[k]);
    imdb_av_str(&r, "a string");
    const char *meta[] = {"k1", "v1", "format-version", "3"};
    uint8_t sync[16];
    for (int k = 0; k < 16; k++) sync[k] = (uint8_t)(k * 17 + 3);
    imdb_buf f;
    imdb_buf_init(&f);
    imdb_av_file(&f, "{\"type\":\"record\",\"name\":\"x\",\"fields\":[]}", meta, 2, sync, 1, r.p, r.len);
    OK(imdb_buf_check(&f, E));
    aocf o;
    const char *why = NULL;
    CHECK(aocf_read(f.p, f.len, &o, &why) == 0);
    size_t ml = 0;
    const uint8_t *fv = aocf_meta(&o, "format-version", &ml);
    CHECK(fv && ml == 1 && fv[0] == '3' && o.nrec == 1 && o.rlen == r.len);
    arr ar = {o.records, o.rlen, 0, false};
    for (size_t k = 0; k < sizeof vals / sizeof *vals; k++) CHECK(ar_long(&ar) == vals[k]);
    size_t sl = 0;
    const uint8_t *sp = ar_bytes(&ar, &sl);
    CHECK(!ar.bad && sp && sl == 8 && !memcmp(sp, "a string", 8) && ar.at == ar.n);
    f.p[f.len - 1] ^= 1; /* the closing marker */
    CHECK(aocf_read(f.p, f.len, &o, &why) != 0);
    imdb_buf_free(&f);
    imdb_buf_free(&r);
}

/* ---- the layer against the database ---- */

static int run(imdb_session *s, const char *q)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(s, q, strlen(q), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

static int64_t count_as_of(imdb_session *s, uint64_t S)
{
    char q[128];
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM t AS OF %llu", (unsigned long long)S);
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(s, q, strlen(q), NULL, 0, &r, &g_e)) return -1;
    int64_t v = r.nrows == 1 && !r.cells[0].null ? (r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i) : -1;
    imdb_result_free(&r);
    return v;
}

static uint8_t *read_at(const char *dir, const char *name, size_t *n)
{
    char p[1200];
    snprintf(p, sizeof p, "%s/%s", dir, name);
    return slurp(p, n);
}

/* the name of a table's current metadata file, by its version hint (v<K>.metadata.json): "" when there is none */
static void cur_meta(const char *mdir, char *out, size_t cap)
{
    size_t hl = 0;
    uint8_t *hb = read_at(mdir, "version-hint.text", &hl);
    if (hb && hl > 0 && hl < 24) snprintf(out, cap, "v%.*s.metadata.json", (int)hl, (const char *)hb);
    else if (cap) out[0] = 0;
    free(hb);
}

/* a snapshot's visible rows by the layer: each data file's records less its deletion vector's (the auditor's readers) */
static int64_t layer_rows(const char *mdir, const char *list_path)
{
    const char *slash = strrchr(list_path, '/');
    size_t n = 0;
    uint8_t *lb = read_at(mdir, slash ? slash + 1 : list_path, &n);
    if (!lb) return -1;
    aocf o;
    const char *why;
    int64_t rows = 0;
    if (aocf_read(lb, n, &o, &why)) {
        free(lb);
        return -1;
    }
    arr r = {o.records, o.rlen, 0, false};
    for (uint64_t k = 0; k < o.nrec && !r.bad; k++) { /* a manifest_file record (iceberg.c's kListSchema) */
        size_t pl;
        const uint8_t *pp = ar_bytes(&r, &pl);
        for (int q = 0; q < 2; q++) (void)ar_long(&r);      /* manifest_length, partition_spec_id */
        int64_t content = ar_long(&r);
        for (int q = 0; q < 9; q++) (void)ar_long(&r);      /* sequence numbers, snapshot, counts */
        if (ar_long(&r)) (void)ar_long(&r);                 /* first_row_id */
        char mp[1200];
        snprintf(mp, sizeof mp, "%.*s", (int)pl, pp ? (const char *)pp : "");
        const char *ms = strrchr(mp, '/');
        size_t mn = 0;
        uint8_t *mb = read_at(mdir, ms ? ms + 1 : mp, &mn);
        aocf mo;
        if (!mb || aocf_read(mb, mn, &mo, &why)) {
            free(mb);
            rows = -1;
            break;
        }
        arr er = {mo.records, mo.rlen, 0, false};
        for (uint64_t x = 0; x < mo.nrec && !er.bad; x++) { /* a manifest_entry record (kEntrySchema) */
            (void)ar_long(&er);                             /* status */
            for (int q = 0; q < 3; q++)
                if (ar_long(&er)) (void)ar_long(&er);       /* snapshot_id, sequence numbers */
            (void)ar_long(&er);                             /* content */
            size_t l;
            (void)ar_bytes(&er, &l);                        /* file_path */
            (void)ar_bytes(&er, &l);                        /* file_format */
            int64_t count = ar_long(&er);
            (void)ar_long(&er);                             /* file_size_in_bytes */
            if (ar_long(&er)) (void)ar_long(&er);           /* first_row_id */
            if (ar_long(&er)) (void)ar_bytes(&er, &l);      /* referenced_data_file */
            if (ar_long(&er)) (void)ar_long(&er);           /* content_offset */
            if (ar_long(&er)) (void)ar_long(&er);           /* content_size_in_bytes */
            rows += content == 0 ? count : -count;          /* a vector's record count its cardinality */
        }
        if (er.bad) rows = -1;
        free(mb);
        if (rows < 0) break;
    }
    if (r.bad) rows = -1;
    free(lb);
    return rows;
}

/* every file in dir: names and bytes, concatenated in name order (the layer's state) */
static char *dir_state(const char *dir, size_t *len)
{
    char *names[256];
    int n = 0;
    DIR *d = opendir(dir);
    struct dirent *de;
    while (d && n < 256 && (de = readdir(d)))
        if (de->d_name[0] != '.') names[n++] = strdup(de->d_name);
    if (d) closedir(d);
    for (int a = 0; a < n; a++)
        for (int b = a + 1; b < n; b++)
            if (strcmp(names[a], names[b]) > 0) {
                char *t = names[a];
                names[a] = names[b];
                names[b] = t;
            }
    imdb_buf out;
    imdb_buf_init(&out);
    for (int k = 0; k < n; k++) {
        size_t fl = 0;
        uint8_t *fb = read_at(dir, names[k], &fl);
        imdb_buf_put_str(&out, names[k]);
        imdb_buf_put_u8(&out, 0);
        if (fb) imdb_buf_put(&out, fb, fl);
        free(fb);
        free(names[k]);
    }
    char *s = malloc(out.len + 1);
    if (s) memcpy(s, out.p, out.len);
    *len = out.len;
    imdb_buf_free(&out);
    return s;
}

/* the auditor's verdict on dir (its own readers and model check the layer: tools/audit/audit.c check_iceberg): 0 taken, 1
 * refused, -1 no auditor in this build */
static int audit_dir(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return -1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0 ? 0 : 1;
}

/* a table's layer at two snapshots, its rows against AS OF, written again the same, VERIFY taking it and refusing a
 * flipped byte, then an ERASE: one snapshot, the earlier ones' files gone, its rows against the table's */
static void t_ice_layer(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_open_opts o = {.sync = 0, .iceberg = true};
    imdb_db *db = NULL;
    OK(imdb_open(dir, &o, &db, E));
    if (!db) return;
    CHECK(db->location != NULL);
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE t (id BIGINT PRIMARY KEY, u BIGINT SUBJECT, x TEXT, n INTEGER)"));
    OK(run(&s, "INSERT INTO t VALUES (1, 42, 'one', 1), (2, 7, 'two', 2), (3, 42, 'three', NULL), (4, 9, 'four', 4)"));
    OK(run(&s, "CHECKPOINT"));
    uint64_t S1 = db->seq;
    OK(run(&s, "UPDATE t SET x = 'two, again' WHERE id = 2"));
    OK(run(&s, "DELETE FROM t WHERE id = 4"));
    OK(run(&s, "INSERT INTO t VALUES (5, 42, 'five', 5)"));
    OK(run(&s, "CHECKPOINT"));
    uint64_t S2 = db->seq;
    char mdir[800], name[64];
    snprintf(mdir, sizeof mdir, "%s/iceberg/%u/metadata", dir, (unsigned)imdb_table_by_name(db, "t")->s.id);
    cur_meta(mdir, name, sizeof name); /* t changed at S2: v(2 S2), with its older snapshot S1 */
    CHECK(name[0] && strtoull(name + 1, NULL, 10) == 2 * S2);
    size_t ml = 0;
    uint8_t *mb = read_at(mdir, name, &ml);
    CHECK(mb);
    aj m;
    const char *why = NULL;
    CHECK(mb && aj_parse((const char *)mb, ml, &m, &why) == 0);
    const aj *snaps = aj_get(&m, "snapshots"), *fv = aj_get(&m, "format-version"), *cur = aj_get(&m, "current-snapshot-id");
    CHECK(fv && fv->kind == AJ_INT && fv->i == 3 && cur && cur->kind == AJ_INT && cur->i == (int64_t)S2);
    CHECK(snaps && snaps->kind == AJ_ARR && snaps->n == 2);
    for (size_t k = 0; snaps && k < snaps->n; k++) { /* each snapshot's rows, by the layer, are AS OF's */
        const aj *id = aj_get(&snaps->v[k], "snapshot-id"), *ls = aj_get(&snaps->v[k], "manifest-list");
        CHECK(id && id->kind == AJ_INT && (id->i == (int64_t)S1 || id->i == (int64_t)S2) && ls && ls->kind == AJ_STR);
        if (!id || !ls || ls->kind != AJ_STR) continue;
        int64_t want = count_as_of(&s, (uint64_t)id->i), got = layer_rows(mdir, ls->s);
        if (got != want) fprintf(stderr, "    snapshot %lld: the layer's %lld rows, AS OF's %lld\n", (long long)id->i, (long long)got,
                                 (long long)want);
        CHECK(got == want && want > 0);
    }
    aj_free(&m);
    free(mb);
    /* written again: the same bytes */
    size_t l1 = 0, l2 = 0;
    char *st1 = dir_state(mdir, &l1);
    OK(imdb_iceberg_write(db, db->location, E));
    char *st2 = dir_state(mdir, &l2);
    CHECK(st1 && st2 && l1 == l2 && !memcmp(st1, st2, l1));
    free(st1);
    free(st2);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    CHECK(vr.iceberg);
    CHECK(audit_dir(dir) != 1);
    /* a byte flipped in a deletion vector's bitmap: the auditor refuses it by its CRC, VERIFY by its bytes */
    DIR *dd = opendir(mdir);
    struct dirent *dv = NULL;
    char vname[128] = "";
    while (dd && (dv = readdir(dd)))
        if (!strncmp(dv->d_name, "dv-", 3)) snprintf(vname, sizeof vname, "%s", dv->d_name);
    if (dd) closedir(dd);
    CHECK(vname[0]);
    size_t vl = 0;
    uint8_t *vb = vname[0] ? read_at(mdir, vname, &vl) : NULL;
    if (vb && vl > 20) {
        char vp[1000];
        snprintf(vp, sizeof vp, "%s/%s", mdir, vname);
        vb[12] ^= 0x04;
        spit(vp, vb, vl);
        CHECK(audit_dir(dir) != 0);
        imdb_err_clear(E);
        CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY);
        vb[12] ^= 0x04;
        spit(vp, vb, vl);
    }
    free(vb);
    /* a byte flipped in the head's data manifest: VERIFY names it */
    char mname[96];
    snprintf(mname, sizeof mname, "m-%llu-%llu-data.avro", (unsigned long long)S2, (unsigned long long)S1); /* the head's, its older S1 */
    size_t fl = 0;
    uint8_t *fb = read_at(mdir, mname, &fl);
    CHECK(fb && fl > 40);
    if (fb && fl > 40) {
        char fp[1000];
        snprintf(fp, sizeof fp, "%s/%s", mdir, mname);
        fb[fl / 2] ^= 0x20;
        spit(fp, fb, fl);
        imdb_err_clear(E);
        CHECK(imdb_verify(db, &vr, E) == IMDB_ERR_VERIFY && strstr(g_e.msg, mname));
        fb[fl / 2] ^= 0x20;
        spit(fp, fb, fl);
        imdb_err_clear(E);
        OK(imdb_verify(db, &vr, E));
    }
    free(fb);
    /* an ERASE keeps no generation beside its own: one snapshot, every file of the ones before gone */
    OK(run(&s, "ERASE SUBJECT 42"));
    uint64_t S3 = db->lake_seq;
    CHECK(S3 > S2);
    DIR *d = opendir(mdir); /* the table alone at S3 (an ERASE changes every table): its files named by S3 alone */
    struct dirent *de;
    char want[4][64];
    snprintf(want[0], sizeof want[0], "snap-%llu.avro", (unsigned long long)S3);
    snprintf(want[1], sizeof want[1], "m-%llu-data.avro", (unsigned long long)S3);
    snprintf(want[2], sizeof want[2], "m-%llu-dv.avro", (unsigned long long)S3);
    snprintf(want[3], sizeof want[3], "v%llu.metadata.json", (unsigned long long)(2 * S3 + 1));
    while (d && (de = readdir(d))) {
        if (de->d_name[0] == '.' || !strncmp(de->d_name, "dv-", 3) || !strcmp(de->d_name, "version-hint.text")) continue;
        bool ok = false;
        for (int k = 0; k < 4 && !ok; k++) ok = !strcmp(de->d_name, want[k]);
        if (!ok) fprintf(stderr, "    %s stays after the ERASE\n", de->d_name);
        CHECK(ok);
    }
    if (d) closedir(d);
    cur_meta(mdir, name, sizeof name);
    CHECK(!strcmp(name, want[3]));
    mb = read_at(mdir, name, &ml);
    CHECK(mb && aj_parse((const char *)mb, ml, &m, &why) == 0);
    snaps = mb ? aj_get(&m, "snapshots") : NULL;
    CHECK(snaps && snaps->n == 1);
    if (snaps && snaps->n == 1) {
        const aj *ls = aj_get(&snaps->v[0], "manifest-list");
        CHECK(ls && ls->kind == AJ_STR && layer_rows(mdir, ls->s) == count_as_of(&s, S3));
    }
    snprintf(name, sizeof name, "v%llu.metadata.json", (unsigned long long)(2 * S2)); /* the head before's, with its older */
    CHECK(!read_at(mdir, name, &ml));
    if (mb) aj_free(&m);
    free(mb);
    OK(imdb_verify(db, &vr, E));
    CHECK(vr.iceberg);
    CHECK(audit_dir(dir) != 1); /* the auditor takes the ERASE's layer */
    imdb_session_close(&s);
    imdb_close(db);
}

/* the auditor's verdict and whether its words hold needle: 0 taken, 1 refused saying it, 2 refused otherwise, -1 no
 * auditor in this build */
static int audit_says(const char *dir, const char *needle)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return -1;
    char out[800], cmd[2400];
    snprintf(out, sizeof out, "%s-audit.txt", dir);
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' > '%s' 2>&1", bin, dir, out);
    int st = system(cmd);
    size_t n = 0;
    uint8_t *b = slurp(out, &n);
    bool has = b && needle && mem_contains(b, n, needle);
    if (st != 0 && !has) fprintf(stderr, "    the auditor: %.*s\n", (int)(n > 400 ? 400 : n), b ? (const char *)b : "");
    free(b);
    unlink(out);
    return st == 0 ? 0 : has ? 1 : 2;
}

static imdb_db *ice_open(const char *dir)
{
    imdb_open_opts o = {.sync = 0, .iceberg = true};
    imdb_db *db = NULL;
    imdb_err_clear(E);
    if (imdb_open(dir, &o, &db, E)) return NULL;
    db->no_auto_retire = true;
    return db;
}

/* the number of snapshots table name's layer holds at the head (-1: none readable) */
static int ice_nsnaps(imdb_db *db, const char *dir, const char *name)
{
    const imdb_table *t = imdb_table_by_name(db, name);
    if (!t) return -1;
    char mdir[800], f[64];
    snprintf(mdir, sizeof mdir, "%s/iceberg/%u/metadata", dir, (unsigned)t->s.id);
    cur_meta(mdir, f, sizeof f); /* by its version hint */
    size_t ml = 0;
    uint8_t *mb = read_at(mdir, f, &ml);
    aj m;
    const char *why;
    int n = -1;
    if (mb && !aj_parse((const char *)mb, ml, &m, &why)) {
        const aj *sn = aj_get(&m, "snapshots");
        n = sn && sn->kind == AJ_ARR ? (int)sn->n : -1;
        aj_free(&m);
    }
    free(mb);
    return n;
}

static bool ice_verified(imdb_db *db)
{
    imdb_verify_report vr;
    imdb_err_clear(E);
    return imdb_verify(db, &vr, E) == 0 && vr.iceberg && !vr.iceberg_stale;
}

/* well-formed lies, each the writer's own but for one rule (iceberg.h's ICE_LIE_*): each refused by the auditor by
 * that rule's words, and by VERIFY once the writer tells the truth again; the truth then taken by both */
static void t_ice_lies(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE t (id BIGINT PRIMARY KEY, x TEXT, n INTEGER NOT NULL)"));
    OK(run(&s, "INSERT INTO t VALUES (1, 'a', 1), (2, 'b', 2), (3, 'c', 3), (4, 'd', 4), (5, 'e', 5)"));
    OK(run(&s, "CHECKPOINT"));
    OK(run(&s, "ALTER TABLE t ADD COLUMN d BIGINT DEFAULT 7"));
    static const char *const adds[] = { /* each type's initial-default, the auditor's own text of it compared */
        "ALTER TABLE t ADD COLUMN s TEXT DEFAULT 'z\"\\\\ \xc3\xa9'",
        "ALTER TABLE t ADD COLUMN f BOOLEAN DEFAULT TRUE",
        "ALTER TABLE t ADD COLUMN m DECIMAL(10,2) DEFAULT -0.05",
        "ALTER TABLE t ADD COLUMN m2 DECIMAL(4,0) DEFAULT 1420",
        "ALTER TABLE t ADD COLUMN dd DATE DEFAULT DATE '1969-12-31'",
        "ALTER TABLE t ADD COLUMN ts TIMESTAMP DEFAULT TIMESTAMP '2017-11-16 22:31:08.123456'",
        "ALTER TABLE t ADD COLUMN tz TIMESTAMPTZ DEFAULT TIMESTAMPTZ '2017-11-16 22:31:08.123456+00'",
        "ALTER TABLE t ADD COLUMN tm TIME DEFAULT TIME '22:31:08.123456'",
        "ALTER TABLE t ADD COLUMN uu UUID DEFAULT 'f79c3e09-677c-4bbd-a479-3f349cb785e7'",
        "ALTER TABLE t ADD COLUMN bb BYTEA DEFAULT '\\x00ff10'",
        "ALTER TABLE t ADD COLUMN fl DOUBLE PRECISION DEFAULT 2",
    };
    for (size_t k = 0; k < sizeof adds / sizeof *adds; k++) OK(run(&s, adds[k]));
    OK(run(&s, "DELETE FROM t WHERE id IN (2, 4)")); /* two dead rows in the first segment */
    OK(run(&s, "INSERT INTO t (id, x, n, d) VALUES (6, 'f', 6, 8)"));
    OK(run(&s, "CHECKPOINT")); /* the head: the first segment EXISTING with its vector, the second ADDED */
    CHECK(ice_nsnaps(db, dir, "t") == 2 && ice_verified(db));
    CHECK(audit_says(dir, NULL) <= 0);
    static const struct {
        int lie;
        const char *says;
    } L[] = {
        {ICE_LIE_DV_MISSING, "not the rows it holds that are not visible at the snapshot"},
        {ICE_LIE_DV_LIVE, "not the rows it holds that are not visible at the snapshot"},
        {ICE_LIE_FILE_OUT, "not every segment of the generation"},
        {ICE_LIE_ADDED, "is not EXISTING as the older snapshot holds it"},
        {ICE_LIE_REQUIRED, "required is not its column's"},
        {ICE_LIE_DEFAULT, "initial-default is not its missing value"},
        {ICE_LIE_DV_SWAP, "not the rows it holds that are not visible at the snapshot"},
        {ICE_LIE_COUNTS, "its data manifest's counts, sequence numbers or first row are not its entries'"},
        {ICE_LIE_MLEN, "its manifest_length is not its size"},
        {ICE_LIE_FRID, "sequence numbers or first row are not the older snapshot's"},
    };
    for (size_t k = 0; k < sizeof L / sizeof *L; k++) {
        imdb_iceberg_set_lie(L[k].lie);
        OK(imdb_iceberg_write(db, db->location, E));
        CHECK(ice_verified(db)); /* the same lie made again: the writer's own files */
        imdb_iceberg_set_lie(0);
        int a = audit_says(dir, L[k].says);
        if (a != 1 && a != -1) fprintf(stderr, "    lie %d: the auditor %s\n", L[k].lie, a ? "refused it otherwise" : "took it");
        CHECK(a == 1 || a == -1);
        CHECK(!ice_verified(db) && g_e.code == IMDB_ERR_VERIFY); /* the lake gives other files */
        OK(imdb_iceberg_write(db, db->location, E));             /* the truth again, made whole */
        CHECK(audit_says(dir, NULL) <= 0 && ice_verified(db));
    }
    imdb_iceberg_set_lie(0);
    /* a file the layer does not name, a dotfile too: refused by both, then gone with the next layer */
    const char *stray[] = {"stray.avro", ".stray"};
    unsigned tid = (unsigned)imdb_table_by_name(db, "t")->s.id;
    for (int k = 0; k < 2; k++) {
        char sp[900];
        snprintf(sp, sizeof sp, "%s/iceberg/%u/metadata/%s", dir, tid, stray[k]);
        spit(sp, (const uint8_t *)"x", 1);
        int a = audit_says(dir, "is no file of its layer");
        CHECK(a == 1 || a == -1);
        CHECK(!ice_verified(db) && strstr(g_e.msg, "is no file of its layer"));
        OK(imdb_iceberg_write(db, db->location, E));
        struct stat st;
        CHECK(stat(sp, &st) != 0 && audit_says(dir, NULL) <= 0 && ice_verified(db));
    }
    /* a file that cannot be removed (a directory: unlinkat refuses it): the layer fails, no current sidecar over it */
    char sd[900];
    snprintf(sd, sizeof sd, "%s/iceberg/%u/metadata/stray.d", dir, tid);
    CHECK(mkdir(sd, 0700) == 0);
    OK(run(&s, "INSERT INTO t (id, x, n) VALUES (40, 'z', 40)"));
    OK(run(&s, "CHECKPOINT")); /* the publication commits; its layer's failure a warning */
    imdb_verify_report vr2;
    OK(imdb_verify(db, &vr2, E));
    CHECK(vr2.iceberg_stale && !vr2.iceberg); /* the sidecar still names the head before */
    CHECK(rmdir(sd) == 0);
    OK(imdb_iceberg_write(db, db->location, E));
    CHECK(audit_says(dir, NULL) <= 0 && ice_verified(db));
    imdb_session_close(&s);
    imdb_close(db);
}

/* a dropped table's layer goes at the next publication; one standing where the head gives none is refused by both */
static void t_ice_drop(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE a (id BIGINT PRIMARY KEY, v BIGINT)"));
    OK(run(&s, "CREATE TABLE b (id BIGINT PRIMARY KEY, v BIGINT)"));
    OK(run(&s, "INSERT INTO a VALUES (1, 1), (2, 2)"));
    OK(run(&s, "INSERT INTO b VALUES (1, 1)"));
    OK(run(&s, "CHECKPOINT"));
    unsigned aid = (unsigned)imdb_table_by_name(db, "a")->s.id;
    char adir[800], amdir[820], junk[840];
    snprintf(adir, sizeof adir, "%s/iceberg/%u", dir, aid);
    snprintf(amdir, sizeof amdir, "%s/metadata", adir);
    struct stat st;
    CHECK(stat(adir, &st) == 0 && ice_nsnaps(db, dir, "b") == 1);
    OK(run(&s, "DROP TABLE a"));
    OK(run(&s, "INSERT INTO b VALUES (2, 2)"));
    OK(run(&s, "CHECKPOINT"));
    CHECK(stat(adir, &st) != 0 && errno == ENOENT); /* gone with its files */
    CHECK(audit_says(dir, NULL) <= 0 && ice_verified(db));
    CHECK(mkdir(adir, 0700) == 0 && mkdir(amdir, 0700) == 0); /* one left standing */
    snprintf(junk, sizeof junk, "%s/version-hint.text", amdir);
    spit(junk, (const uint8_t *)"1", 1);
    int r = audit_says(dir, "stands where the head gives none");
    CHECK(r == 1 || r == -1);
    CHECK(!ice_verified(db) && strstr(g_e.msg, "stands where the head gives none"));
    OK(run(&s, "INSERT INTO b VALUES (3, 3)"));
    OK(run(&s, "CHECKPOINT")); /* the next layer removes it */
    CHECK(stat(adir, &st) != 0 && audit_says(dir, NULL) <= 0 && ice_verified(db));
    imdb_session_close(&s);
    imdb_close(db);
}

/* every file under dir (relative names and bytes, a location replaced by another of its length), in name order */
static void tree_state(const char *root, const char *rel, const char *from, const char *to, imdb_buf *out)
{
    char p[1200];
    snprintf(p, sizeof p, "%s%s%s", root, rel[0] ? "/" : "", rel);
    DIR *d = opendir(p);
    if (!d) return;
    char *names[512];
    int n = 0;
    for (struct dirent *de; n < 512 && (de = readdir(d));)
        if (de->d_name[0] != '.') names[n++] = strdup(de->d_name);
    closedir(d);
    for (int a = 0; a < n; a++)
        for (int b = a + 1; b < n; b++)
            if (strcmp(names[a], names[b]) > 0) {
                char *x = names[a];
                names[a] = names[b];
                names[b] = x;
            }
    size_t fl = strlen(from);
    for (int k = 0; k < n; k++) {
        char r2[1200], q[1300];
        snprintf(r2, sizeof r2, "%s%s%s", rel, rel[0] ? "/" : "", names[k]);
        snprintf(q, sizeof q, "%s/%s", root, r2);
        struct stat st;
        if (stat(q, &st) == 0 && S_ISDIR(st.st_mode)) {
            tree_state(root, r2, from, to, out);
        } else {
            size_t bl = 0;
            uint8_t *b = slurp(q, &bl);
            for (size_t i = 0; b && fl && i + fl <= bl; i++) /* the location, of the same length: replaced */
                if (!memcmp(b + i, from, fl)) memcpy(b + i, to, fl);
            imdb_buf_put_str(out, r2);
            imdb_buf_put_u8(out, 0);
            if (b) imdb_buf_put(out, b, bl);
            imdb_buf_put_u8(out, 0);
            free(b);
        }
        free(names[k]);
    }
}

/* a replica fed the primary's whole log: its layer the primary's byte for byte but for its location (each the same
 * length here); then a writable open of a stale layer writes it again */
static void t_ice_replica(void)
{
    const char *base = test_tmpdir();
    char p[700], r[700], f[760];
    snprintf(p, sizeof p, "%s-p", base);
    snprintf(r, sizeof r, "%s-r", base);
    snprintf(f, sizeof f, "%s-stream", base);
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = ice_open(p);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE t (id BIGINT PRIMARY KEY, u BIGINT SUBJECT, x TEXT, d DATE, b BYTEA)"));
    OK(run(&s, "INSERT INTO t VALUES (1, 5, 'a', DATE '2026-11-14', '\\x00ff'), (2, 6, 'b', NULL, NULL), (3, 5, 'c', NULL, '\\x01')"));
    OK(run(&s, "CHECKPOINT"));
    OK(run(&s, "ALTER TABLE t ADD COLUMN k INTEGER NOT NULL DEFAULT 3"));
    OK(run(&s, "UPDATE t SET x = 'bb' WHERE id = 2"));
    OK(run(&s, "CHECKPOINT"));
    OK(run(&s, "ERASE SUBJECT 6"));
    OK(run(&s, "INSERT INTO t VALUES (4, 7, 'd', NULL, NULL, 4)"));
    OK(run(&s, "CHECKPOINT"));
    imdb_session_close(&s);
    imdb_identity id;
    OK(imdb_identity_read(p, &id, NULL, &g_e));
    OK(imdb_init_replica(r, &id, &g_e));
    OK(ship_to_file(p, 0, f, &g_e));
    imdb_db *rdb = ice_open(r);
    CHECK(rdb);
    if (!rdb) {
        imdb_close(db);
        return;
    }
    uint64_t applied = 0;
    OK(apply_file(rdb, f, &applied, &g_e));
    CHECK(rdb->seq == db->seq && rdb->lake_seq == db->lake_seq && ice_nsnaps(rdb, r, "t") == ice_nsnaps(db, p, "t"));
    char pi[760], ri[760];
    snprintf(pi, sizeof pi, "%s/iceberg", db->location);
    snprintf(ri, sizeof ri, "%s/iceberg", rdb->location);
    imdb_buf a, b;
    imdb_buf_init(&a);
    imdb_buf_init(&b);
    tree_state(pi, "", db->location, rdb->location, &a);
    tree_state(ri, "", "", "", &b);
    CHECK(a.len > 0 && a.len == b.len && !memcmp(a.p, b.p, a.len));
    imdb_buf_free(&a);
    imdb_buf_free(&b);
    CHECK(ice_verified(rdb));
    imdb_close(rdb);
    CHECK(audit_says(r, NULL) <= 0);
    /* a stale layer (its sidecar another head's): VERIFY reports it, a writable open writes it again */
    char lp[800];
    snprintf(lp, sizeof lp, "%s/iceberg/LAYER", r);
    spit(lp, (const uint8_t *)"imagedb-iceberg 1\nhead 1\nlocation /\n", 36);
    imdb_open_opts ro = {.read_only = true};
    imdb_db *x = NULL;
    OK(imdb_open(r, &ro, &x, E));
    imdb_verify_report vr;
    if (x) {
        OK(imdb_verify(x, &vr, E));
        CHECK(vr.iceberg_stale && !vr.iceberg);
        imdb_close(x);
    }
    rdb = ice_open(r);
    CHECK(rdb && ice_verified(rdb));
    if (rdb) imdb_close(rdb);
    imdb_close(db);
}

/* what the layer reads: a publication reads only the vectors that changed; a handle's first, every kept one once */
static void t_ice_reads(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    keep_in_memory(db); /* every image kept, no window: the counts the layer's alone, whatever the mode */
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE t (id BIGINT PRIMARY KEY, v BIGINT)"));
    char q[128];
    for (int k = 0; k < 6; k++) { /* six segments, each with a dead row */
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 1), (%d, 2), (%d, 3)", 10 * k, 10 * k + 1, 10 * k + 2);
        OK(run(&s, q));
        OK(run(&s, "CHECKPOINT"));
        snprintf(q, sizeof q, "DELETE FROM t WHERE id = %d", 10 * k);
        OK(run(&s, q));
    }
    OK(run(&s, "CHECKPOINT"));
    uint64_t r0 = imdb_iceberg_reads(db), l0 = db->segcache.loads;
    OK(run(&s, "INSERT INTO t VALUES (100, 1)"));
    OK(run(&s, "CHECKPOINT")); /* nothing ended: no vector read */
    CHECK(imdb_iceberg_reads(db) == r0 && db->segcache.loads == l0);
    OK(run(&s, "UPDATE t SET v = 9 WHERE id = 31"));
    OK(run(&s, "CHECKPOINT")); /* one segment's vector changed: it alone read */
    if (imdb_iceberg_reads(db) != r0 + 1) fprintf(stderr, "    reads %llu, not 1\n", (unsigned long long)(imdb_iceberg_reads(db) - r0));
    CHECK(imdb_iceberg_reads(db) == r0 + 1 && db->segcache.loads == l0);
    CHECK(audit_says(dir, NULL) <= 0 && ice_verified(db));
    r0 = imdb_iceberg_reads(db);
    OK(run(&s, "COMPACT t"));
    uint64_t rc1 = imdb_iceberg_reads(db) - r0; /* the compaction's own segments' vectors: what changed */
    r0 = imdb_iceberg_reads(db);
    OK(run(&s, "INSERT INTO t VALUES (101, 1)"));
    OK(run(&s, "CHECKPOINT")); /* the older generation the compaction's: found by the last layer, unread */
    if (imdb_iceberg_reads(db) != r0) fprintf(stderr, "    reads past COMPACT %llu (its own %llu)\n", (unsigned long long)(imdb_iceberg_reads(db) - r0), (unsigned long long)rc1);
    CHECK(imdb_iceberg_reads(db) == r0);
    CHECK(audit_says(dir, NULL) <= 0 && ice_verified(db));
    imdb_session_close(&s);
    imdb_close(db);
    db = ice_open(dir); /* a handle's first layer reads each kept vector once */
    CHECK(db);
    if (!db) return;
    keep_in_memory(db);
    imdb_session_init(&s, db);
    r0 = imdb_iceberg_reads(db);
    OK(run(&s, "DELETE FROM t WHERE id = 101"));
    OK(run(&s, "CHECKPOINT"));
    uint64_t first = imdb_iceberg_reads(db) - r0;
    r0 = imdb_iceberg_reads(db);
    OK(run(&s, "INSERT INTO t VALUES (102, 1)"));
    OK(run(&s, "CHECKPOINT"));
    CHECK(first >= 1 && imdb_iceberg_reads(db) == r0);
    CHECK(audit_says(dir, NULL) <= 0 && ice_verified(db));
    imdb_session_close(&s);
    imdb_close(db);
}

/* past a RETIRE whose boundary is the older generation's commit: the head alone, a table whose segments it dropped no
 * layer; a replica seeded past the cut and a restored copy (each holding the head generation's objects alone) the head
 * alone; each taken by VERIFY and the auditor */
static void t_ice_cut(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE a (id BIGINT PRIMARY KEY, v BIGINT) RETENTION 10 SECONDS"));
    OK(run(&s, "CREATE TABLE b (id BIGINT PRIMARY KEY, v BIGINT) RETENTION 10 SECONDS"));
    OK(run(&s, "INSERT INTO a VALUES (1, 1), (2, 2), (3, 3)"));
    OK(run(&s, "INSERT INTO b VALUES (1, 1)"));
    OK(run(&s, "CHECKPOINT"));
    OK(run(&s, "UPDATE a SET v = 5 WHERE id = 1"));
    OK(run(&s, "DELETE FROM b WHERE id = 1"));
    OK(run(&s, "CHECKPOINT"));
    uint64_t B = db->seq; /* the last publication's commit: the boundary */
    unsigned bid = (unsigned)imdb_table_by_name(db, "b")->s.id;
    CHECK(ice_nsnaps(db, dir, "a") == 2);
    OK(run(&s, "INSERT INTO a VALUES (9, 9)")); /* B + 1 begins a log segment: the horizons pass B there */
    imdb_clock_offset(15 * 1000000ll);
    OK(run(&s, "SELECT COUNT(*) FROM a"));
    OK(run(&s, "SELECT COUNT(*) FROM b")); /* the expiry policy: each horizon past B */
    imdb_err_clear(E);
    int rr = imdb_retire(db, B, E);
    if (rr) fprintf(stderr, "    retire: %s\n", g_e.msg);
    OK(rr);
    char bdir[800];
    snprintf(bdir, sizeof bdir, "%s/iceberg/%u", dir, bid);
    struct stat st;
    CHECK(ice_nsnaps(db, dir, "a") == 1);         /* the older generation's commit retired: the head alone */
    CHECK(stat(bdir, &st) != 0 && errno == ENOENT); /* b holds no segment: no layer */
    CHECK(ice_verified(db));
    imdb_session_close(&s);
    imdb_close(db);
    CHECK(audit_says(dir, NULL) <= 0);
    /* a replica seeded past the cut */
    char rdir[700], f[760], bk[760], kf[760], rs[760];
    snprintf(rdir, sizeof rdir, "%s-replica", dir);
    snprintf(f, sizeof f, "%s-stream", dir);
    imdb_identity id;
    OK(imdb_identity_read(dir, &id, NULL, &g_e));
    OK(imdb_init_replica(rdir, &id, &g_e));
    OK(ship_to_file(dir, 0, f, &g_e));
    imdb_db *rdb = ice_open(rdir);
    CHECK(rdb);
    if (!rdb) return;
    uint64_t applied = 0;
    OK(apply_file(rdb, f, &applied, &g_e));
    CHECK(rdb->seeded);
    imdb_close(rdb);
    rdb = ice_open(rdir); /* the snapshot open writes its layer: the head alone */
    CHECK(rdb && ice_nsnaps(rdb, rdir, "a") == 1 && ice_verified(rdb));
    /* the replica's own publication, in the handle the snapshot opened: the older generation the seed's, past its floor
     * (the seed's objects its own); then a fresh handle makes the same layer */
    db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    imdb_session_init(&s, db);
    OK(run(&s, "INSERT INTO a VALUES (10, 10)"));
    OK(run(&s, "CHECKPOINT"));
    imdb_session_close(&s);
    int pn = ice_nsnaps(db, dir, "a");
    imdb_close(db);
    OK(ship_to_file(dir, rdb->seq, f, &g_e));
    OK(apply_file(rdb, f, &applied, &g_e));
    int rn = ice_nsnaps(rdb, rdir, "a");
    if (rn != pn || pn != 2) fprintf(stderr, "    primary %d snapshots, replica %d (its lake %llu, floor %llu, the primary's B %llu)\n", pn, rn, (unsigned long long)rdb->lake_seq, (unsigned long long)rdb->log_floor, (unsigned long long)B);
    CHECK(rn == pn && pn == 2);
    imdb_close(rdb);
    rdb = ice_open(rdir);
    CHECK(rdb && ice_verified(rdb));
    if (rdb) imdb_close(rdb);
    CHECK(audit_says(rdir, NULL) <= 0);
    CHECK(audit_says(rdir, NULL) <= 0);
    /* a restored copy */
    uint8_t key[IMDB_BACKUP_KEY_LEN], kid[32];
    snprintf(bk, sizeof bk, "%s-backup", dir);
    snprintf(kf, sizeof kf, "%s-key", dir);
    snprintf(rs, sizeof rs, "%s-restored", dir);
    OK(imdb_backup_key_create(kf, kid, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info bi;
    OK(imdb_backup_full(dir, bk, key, &bi, E));
    const char *files[1] = {bk};
    OK(imdb_restore(rs, key, files, 1, &bi, E));
    rdb = ice_open(rs);
    int rn0 = rdb ? ice_nsnaps(rdb, rs, "a") : -1;
    bool rv0 = rdb && ice_verified(rdb);
    if (rn0 < 1 || !rv0) fprintf(stderr, "    restored: %d snapshots, verify %d (%s)\n", rn0, rv0, g_e.msg);
    CHECK(rdb && rn0 >= 1 && rv0); /* the head, and its older where that generation's objects are on disk (shared here) */
    if (rdb) imdb_close(rdb);
    CHECK(audit_says(rs, NULL) <= 0);
}

/* a restore of a database never retired: the copy's floor its seed's commit, so its first publication's older generation
 * (that commit's, FLOOR's time) is offered by every handle alike, a fresh one too, as the next one's */
static void t_ice_restore(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE a (id BIGINT PRIMARY KEY, v BIGINT)"));
    OK(run(&s, "INSERT INTO a VALUES (1, 1), (2, 2)"));
    OK(run(&s, "CHECKPOINT"));
    OK(run(&s, "UPDATE a SET v = 3 WHERE id = 1"));
    OK(run(&s, "CHECKPOINT"));
    imdb_session_close(&s);
    imdb_close(db);
    char bk[760], kf[760], rs[760], f[760];
    snprintf(bk, sizeof bk, "%s-backup", dir);
    snprintf(kf, sizeof kf, "%s-key", dir);
    snprintf(rs, sizeof rs, "%s-restored", dir);
    snprintf(f, sizeof f, "%s-stream", dir);
    uint8_t key[IMDB_BACKUP_KEY_LEN], kid[32];
    OK(imdb_backup_key_create(kf, kid, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info bi;
    OK(imdb_backup_full(dir, bk, key, &bi, E));
    const char *files[1] = {bk};
    OK(imdb_restore(rs, key, files, 1, &bi, E));
    imdb_db *rdb = ice_open(rs);
    CHECK(rdb);
    if (!rdb) return;
    int rn1 = ice_nsnaps(rdb, rs, "a");
    bool rv1 = ice_verified(rdb);
    if (rn1 < 1 || !rv1) fprintf(stderr, "    restored: %d snapshots, verify %d (%s)\n", rn1, rv1, g_e.msg);
    CHECK(rn1 >= 1 && rv1); /* the head, and its older where that generation's objects are on disk (shared here) */
    for (int round = 0; round < 2; round++) { /* the primary's publications, applied in the copy's opening handle */
        db = ice_open(dir);
        CHECK(db);
        if (!db) break;
        imdb_session_init(&s, db);
        char q[64];
        snprintf(q, sizeof q, "INSERT INTO a VALUES (%d, 1)", 10 + round);
        OK(run(&s, q));
        OK(run(&s, "CHECKPOINT"));
        imdb_session_close(&s);
        imdb_close(db);
        uint64_t applied = 0;
        OK(ship_to_file(dir, rdb->seq, f, &g_e));
        OK(apply_file(rdb, f, &applied, &g_e));
        int n = ice_nsnaps(rdb, rs, "a");
        if (n != 2) fprintf(stderr, "    round %d: %d snapshots (the floor %llu)\n", round, n, (unsigned long long)rdb->log_floor);
        CHECK(n == 2 && ice_verified(rdb)); /* the older the seed's generation at the floor, then the copy's own */
        imdb_close(rdb);
        rdb = ice_open(rs); /* a fresh handle: the same layer */
        CHECK(rdb && ice_verified(rdb));
        CHECK(audit_says(rs, NULL) <= 0);
    }
    if (rdb) imdb_close(rdb);
}

/* each type's initial-default in Iceberg's single-value serialization, against the spec's own examples (Appendix D) */
static void t_ice_values(void)
{
    static const uint8_t uu[16] = {0xf7, 0x9c, 0x3e, 0x09, 0x67, 0x7c, 0x4b, 0xbd, 0xa4, 0x79, 0x3f, 0x34, 0x9c, 0xb7, 0x85, 0xe7};
    static const uint8_t bin[4] = {0x00, 0x01, 0x02, 0xff};
    struct {
        uint8_t type, prec, scale;
        int64_t i;
        const uint8_t *s;
        uint32_t len;
        const char *want;
    } V[] = {
        {IMDB_T_BOOL, 0, 0, 1, NULL, 0, "true"},
        {IMDB_T_INT64, 32, 0, 34, NULL, 0, "34"},
        {IMDB_T_INT64, 0, 0, 34, NULL, 0, "34"},
        {IMDB_T_DECIMAL, 4, 2, 1420, NULL, 0, "\"14.20\""},
        {IMDB_T_DATE, 0, 0, 17486, NULL, 0, "\"2017-11-16\""},
        {IMDB_T_TIME, 0, 0, 81068123456ll, NULL, 0, "\"22:31:08.123456\""},
        {IMDB_T_TIMESTAMP, 0, 0, 1510871468123456ll, NULL, 0, "\"2017-11-16T22:31:08.123456\""},
        {IMDB_T_TIMESTAMPTZ, 0, 0, 1510871468123456ll, NULL, 0, "\"2017-11-16T22:31:08.123456+00:00\""},
        {IMDB_T_TEXT, 0, 0, 0, (const uint8_t *)"iceberg", 7, "\"iceberg\""},
        {IMDB_T_UUID, 0, 0, 0, uu, 16, "\"f79c3e09-677c-4bbd-a479-3f349cb785e7\""},
        {IMDB_T_BYTEA, 0, 0, 0, bin, 4, "\"000102ff\""},
        {IMDB_T_TIMESTAMP, 0, 0, -1, NULL, 0, "\"1969-12-31T23:59:59.999999\""},
    };
    for (size_t k = 0; k < sizeof V / sizeof *V; k++) {
        imdb_column c;
        memset(&c, 0, sizeof c);
        c.type = V[k].type;
        c.precision = V[k].prec;
        c.scale = V[k].scale;
        imdb_value v;
        memset(&v, 0, sizeof v);
        v.type = V[k].type;
        v.scale = V[k].scale;
        v.i = V[k].i;
        if (V[k].s) {
            v.s = V[k].s;
            v.len = V[k].len;
        }
        imdb_buf b;
        imdb_buf_init(&b);
        imdb_iceberg_value_json(&c, &v, &b);
        imdb_buf_put_u8(&b, 0);
        bool ok = !b.err && !strcmp((const char *)b.p, V[k].want);
        if (!ok) fprintf(stderr, "    %s, not %s\n", b.p ? (const char *)b.p : "?", V[k].want);
        CHECK(ok);
        imdb_buf_free(&b);
    }
    imdb_column c; /* a double: a fraction always */
    memset(&c, 0, sizeof c);
    c.type = IMDB_T_FLOAT64;
    imdb_value v;
    memset(&v, 0, sizeof v);
    v.type = IMDB_T_FLOAT64;

    v.i = imdb_f64_key(2.0);
    imdb_buf b;
    imdb_buf_init(&b);
    imdb_iceberg_value_json(&c, &v, &b);
    imdb_buf_put_u8(&b, 0);
    CHECK(!b.err && (!strcmp((const char *)b.p, "2.0") || strchr((const char *)b.p, 'e')));
    imdb_buf_free(&b);
}

/* table name's last change and its time in the head manifest (manifest 21): 0 when it cannot be read */
static uint64_t head_changed(imdb_db *db, const char *name, uint64_t *us)
{
    const imdb_table *t = imdb_table_by_name(db, name);
    imdb_manifest m;
    imdb_err e2 = {0};
    if (!t || !db->lake_mbytes || imdb_manifest_parse(db->lake_mbytes, db->lake_mlen, &m, &e2)) return 0;
    uint64_t c = t->s.id < m.nt ? m.t[t->s.id].changed : 0;
    if (us) *us = t->s.id < m.nt ? m.t[t->s.id].changed_us : 0;
    imdb_manifest_free(&m);
    return c;
}

/* the publication's own: changed at it, the time of the commit before it */
static bool changed_here(imdb_db *db, const char *name)
{
    uint64_t us = 0, c = head_changed(db, name, &us);
    imdb_err e2 = {0};
    const imdb_commit_info *ci = imdb_ci_at(db, db->lake_seq - 1, &e2);
    if (c != db->lake_seq || !ci || us != ci->time_us)
        fprintf(stderr, "    %s: changed %llu at %llu, the head %llu\n", name, (unsigned long long)c, (unsigned long long)us,
                (unsigned long long)db->lake_seq);
    return c == db->lake_seq && ci && us == ci->time_us;
}

/* F5c stage 2 (manifest 21): each kind of change alone, its table's last change moved exactly when the layer reads what it
 * changed (a write, an ALTER with no row, a COMPACT; an ERASE every table), carried over otherwise (another table's write,
 * an index, an expiry's horizon), each publication taken by VERIFY's and the auditor's one-step rule */
static void t_ice_changed(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE a (id BIGINT PRIMARY KEY, u BIGINT SUBJECT, v BIGINT)"));
    OK(run(&s, "CREATE TABLE b (id BIGINT PRIMARY KEY, v BIGINT)"));
    OK(run(&s, "CREATE TABLE c (id BIGINT PRIMARY KEY, v BIGINT) RETENTION 10 SECONDS"));
    OK(run(&s, "INSERT INTO a VALUES (1, 42, 1), (2, 7, 2)"));
    OK(run(&s, "INSERT INTO b VALUES (1, 1), (2, 2)"));
    OK(run(&s, "INSERT INTO c VALUES (1, 1), (2, 2)"));
    OK(run(&s, "UPDATE c SET v = 3 WHERE id = 1"));
    OK(run(&s, "CHECKPOINT"));
    uint64_t p1 = db->lake_seq;
    CHECK(changed_here(db, "a") && changed_here(db, "b") && changed_here(db, "c"));
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    OK(run(&s, "INSERT INTO a VALUES (3, 7, 3)")); /* another table's write: b and c carried */
    OK(run(&s, "CHECKPOINT"));
    CHECK(changed_here(db, "a") && head_changed(db, "b", NULL) == p1 && head_changed(db, "c", NULL) == p1);
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    OK(run(&s, "CREATE INDEX b_v ON b (v)")); /* an index: not what the layer reads */
    OK(run(&s, "INSERT INTO a VALUES (4, 7, 4)"));
    OK(run(&s, "CHECKPOINT"));
    CHECK(changed_here(db, "a") && head_changed(db, "b", NULL) == p1);
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    OK(run(&s, "ALTER TABLE b ADD COLUMN w BIGINT DEFAULT 5")); /* an ALTER with no row: b's history */
    OK(run(&s, "INSERT INTO a VALUES (5, 7, 5)"));
    OK(run(&s, "CHECKPOINT"));
    CHECK(changed_here(db, "b") && head_changed(db, "c", NULL) == p1);
    uint64_t pb = db->lake_seq;
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    imdb_clock_offset(15 * 1000000ll); /* c's expiry: its horizon moves, its segments and history do not */
    OK(run(&s, "SELECT COUNT(*) FROM c"));
    OK(run(&s, "INSERT INTO a VALUES (6, 7, 6)"));
    OK(run(&s, "CHECKPOINT"));
    CHECK(changed_here(db, "a") && head_changed(db, "b", NULL) == pb && head_changed(db, "c", NULL) == p1);
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    OK(run(&s, "COMPACT b")); /* its segments rewritten */
    CHECK(changed_here(db, "b") && head_changed(db, "c", NULL) == p1);
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    OK(run(&s, "ERASE SUBJECT 42")); /* an ERASE: every table */
    CHECK(changed_here(db, "a") && changed_here(db, "b") && changed_here(db, "c"));
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    OK(run(&s, "INSERT INTO b (id, v) VALUES (9, 9)"));
    OK(run(&s, "CHECKPOINT")); /* after it, by comparison again */
    uint64_t pe = db->lake_seq;
    CHECK(changed_here(db, "b") && head_changed(db, "a", NULL) < pe && head_changed(db, "c", NULL) < pe);
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    imdb_session_close(&s);
    imdb_close(db);
    db = ice_open(dir); /* the next publication of another handle: compares with the same head */
    CHECK(db);
    if (!db) return;
    imdb_session_init(&s, db);
    OK(run(&s, "INSERT INTO c VALUES (7, 7)"));
    OK(run(&s, "CHECKPOINT"));
    CHECK(changed_here(db, "c") && head_changed(db, "b", NULL) == pe);
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    /* a RENAME TABLE alone (the advisor, 2026-11-15): the name is in the schema's span (the layer's imagedb.table
     * property), so b2 changed at the next publication though another table's write made it; then written alone, then
     * left untouched under its new name, each taken by VERIFY and the auditor */
    OK(run(&s, "ALTER TABLE b RENAME TO b2"));
    OK(run(&s, "INSERT INTO c VALUES (8, 8)"));
    OK(run(&s, "CHECKPOINT"));
    uint64_t pr = db->lake_seq;
    CHECK(changed_here(db, "b2"));
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    char q[64];
    for (int k = 0; k < 2; k++) {
        snprintf(q, sizeof q, "INSERT INTO c VALUES (%d, 9)", 10 + k);
        OK(run(&s, q));
        OK(run(&s, "CHECKPOINT"));
        CHECK(head_changed(db, "b2", NULL) == pr && ice_nsnaps(db, dir, "b2") == 1);
        CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    }
    imdb_session_close(&s);
    imdb_close(db);
}

/* the bytes of every file under a table's layer (names and contents), to tell it was not touched */
static char *table_state(const char *dir, const imdb_table *t, size_t *len)
{
    char mdir[800];
    snprintf(mdir, sizeof mdir, "%s/iceberg/%u/metadata", dir, (unsigned)t->s.id);
    return dir_state(mdir, len);
}

/* F5c stage 2: a publication touches only the tables that changed (f5c-design 9.1): on 20 tables, a CHECKPOINT that
 * changes one writes that table's layer (twice: at its change, then alone at the next publication) and leaves every
 * other table's files as they were, its syncs a few whatever the tables; VERIFY and the auditor take each */
static void t_ice_untouched(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_open_opts o = {.sync = 1, .iceberg = true};
    imdb_db *db = NULL;
    OK(imdb_open(dir, &o, &db, E));
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    char q[160];
    for (int k = 0; k < 20; k++) {
        snprintf(q, sizeof q, "CREATE TABLE t%d (id BIGINT PRIMARY KEY, v BIGINT)", k);
        OK(run(&s, q));
        snprintf(q, sizeof q, "INSERT INTO t%d VALUES (1, 1), (2, 2)", k);
        OK(run(&s, q));
    }
    OK(run(&s, "CHECKPOINT"));
    OK(run(&s, "INSERT INTO t0 VALUES (3, 3)"));
    OK(run(&s, "CHECKPOINT")); /* t0 with two snapshots, the rest alone (unchanged since the first) */
    OK(run(&s, "INSERT INTO t1 VALUES (3, 3)"));
    OK(run(&s, "CHECKPOINT")); /* t1 changes; t0 goes alone */
    CHECK(ice_nsnaps(db, dir, "t0") == 1 && ice_nsnaps(db, dir, "t1") == 2 && ice_nsnaps(db, dir, "t7") == 1);
    size_t l7 = 0, l9 = 0;
    char *s7 = table_state(dir, imdb_table_by_name(db, "t7"), &l7), *s9 = table_state(dir, imdb_table_by_name(db, "t9"), &l9);
    imdb_hist h0, h1;
    OK(run(&s, "INSERT INTO t2 VALUES (3, 3)"));
    imdb_io_sync_stats(&h0);
    OK(run(&s, "CHECKPOINT")); /* t2 changes, t1 goes alone; 17 tables untouched */
    imdb_io_sync_stats(&h1);
    uint64_t syncs = h1.n - h0.n;
    size_t m7 = 0, m9 = 0;
    char *n7 = table_state(dir, imdb_table_by_name(db, "t7"), &m7), *n9 = table_state(dir, imdb_table_by_name(db, "t9"), &m9);
    CHECK(s7 && n7 && l7 == m7 && !memcmp(s7, n7, l7) && s9 && n9 && l9 == m9 && !memcmp(s9, n9, l9));
    if (syncs > 40) fprintf(stderr, "    a publication touching two tables of 20: %llu syncs\n", (unsigned long long)syncs);
    CHECK(syncs <= 40); /* the lake's own and two tables' layers, never 20 tables' */
    free(s7), free(n7), free(s9), free(n9);
    CHECK(ice_nsnaps(db, dir, "t1") == 1 && ice_nsnaps(db, dir, "t2") == 2);
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    imdb_session_close(&s);
    imdb_close(db);
    db = ice_open(dir); /* another handle: the same layer, nothing written at its open */
    CHECK(db && ice_verified(db));
    if (db) imdb_close(db);
}


/* the inodes of a table's Puffin files, by name (a file written again is renamed into place: another inode) */
static int puffins(const char *dir, const imdb_table *t, char names[][96], ino_t *ino, int cap)
{
    char mdir[800];
    snprintf(mdir, sizeof mdir, "%s/iceberg/%u/metadata", dir, (unsigned)t->s.id);
    DIR *d = opendir(mdir);
    struct dirent *de;
    int n = 0;
    while (d && n < cap && (de = readdir(d))) {
        size_t l = strlen(de->d_name);
        if (l < 7 || l >= 96 || strcmp(de->d_name + l - 7, ".puffin")) continue;
        char fp[900];
        snprintf(fp, sizeof fp, "%s/%s", mdir, de->d_name);
        struct stat st;
        if (stat(fp, &st) != 0) continue;
        memcpy(names[n], de->d_name, l + 1);
        ino[n++] = st.st_ino;
    }
    if (d) closedir(d);
    return n;
}

/* a table left untouched keeps what the last layer found for its vectors (the advisor, 2026-11-14 22:1x): t, six segments
 * each with a dead row, is left alone by two publications that change u alone; then one of its rows changes: the next
 * layer reads that segment's new vector alone and writes no other Puffin file again, as when t changed at every one */
static void t_ice_idle(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    keep_in_memory(db); /* every image kept, no window: the counts the layer's alone, whatever the mode */
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE t (id BIGINT PRIMARY KEY, v BIGINT)"));
    OK(run(&s, "CREATE TABLE u (id BIGINT PRIMARY KEY, v BIGINT)"));
    char q[128];
    for (int k = 0; k < 6; k++) { /* six segments, each with a dead row */
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, 1), (%d, 2), (%d, 3)", 10 * k, 10 * k + 1, 10 * k + 2);
        OK(run(&s, q));
        OK(run(&s, "CHECKPOINT"));
        snprintf(q, sizeof q, "DELETE FROM t WHERE id = %d", 10 * k);
        OK(run(&s, q));
    }
    OK(run(&s, "INSERT INTO u VALUES (1, 1)"));
    OK(run(&s, "CHECKPOINT"));
    for (int k = 2; k <= 4; k++) { /* u alone: t written alone once, then left untouched twice */
        snprintf(q, sizeof q, "INSERT INTO u VALUES (%d, 1)", k);
        OK(run(&s, q));
        OK(run(&s, "CHECKPOINT"));
    }
    const imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t);
    if (!t) {
        imdb_session_close(&s);
        imdb_close(db);
        return;
    }
    char n0[16][96], n1[16][96];
    ino_t i0[16], i1[16];
    int c0 = puffins(dir, t, n0, i0, 16);
    CHECK(c0 == 6);
    uint64_t r0 = imdb_iceberg_reads(db);
    OK(run(&s, "UPDATE t SET v = 9 WHERE id = 31"));
    OK(run(&s, "CHECKPOINT")); /* one vector changed: it alone read */
    uint64_t reads = imdb_iceberg_reads(db) - r0;
    int c1 = puffins(dir, t, n1, i1, 16), kept = 0, again = 0;
    for (int a = 0; a < c0; a++)
        for (int b = 0; b < c1; b++)
            if (!strcmp(n0[a], n1[b])) i0[a] == i1[b] ? kept++ : again++;
    if (reads != 1 || again || kept != 6) fprintf(stderr, "    reads %llu, Puffin files kept %d, written again %d\n", (unsigned long long)reads, kept, again);
    CHECK(reads == 1 && again == 0 && kept == 6 && c1 == 7); /* the six the older snapshot reads, the changed one new */
    CHECK(audit_says(dir, NULL) <= 0 && ice_verified(db));
    imdb_session_close(&s);
    imdb_close(db);
}


/* the older snapshot never below the table's horizon at the head (f5c-design 9.4): a COMPACT's PURGE BEFORE at the
 * retained generation's commit keeps both (imagedb answers AS OF there), one past it leaves the head alone (imagedb
 * refuses AS OF there, and that generation's files still hold the versions purged); VERIFY and the auditor take each */
static void t_ice_horizon(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = ice_open(dir);
    CHECK(db);
    if (!db) return;
    imdb_session s;
    imdb_session_init(&s, db);
    OK(run(&s, "CREATE TABLE a (id BIGINT PRIMARY KEY, v BIGINT)"));
    OK(run(&s, "CREATE TABLE b (id BIGINT PRIMARY KEY, v BIGINT)"));
    OK(run(&s, "INSERT INTO a VALUES (1, 1), (2, 2)"));
    OK(run(&s, "INSERT INTO b VALUES (1, 1), (2, 2)"));
    OK(run(&s, "CHECKPOINT"));
    OK(run(&s, "UPDATE a SET v = 10 WHERE id = 1"));
    OK(run(&s, "UPDATE b SET v = 10 WHERE id = 1"));
    OK(run(&s, "CHECKPOINT"));
    uint64_t P = db->lake_seq; /* what the COMPACT's publication retains */
    char q[160];
    snprintf(q, sizeof q, "COMPACT a PURGE BEFORE %llu", (unsigned long long)P);
    OK(run(&s, q)); /* the horizon at P itself: AS OF P answered, so both snapshots */
    CHECK(ice_nsnaps(db, dir, "a") == 2 && ice_nsnaps(db, dir, "b") == 1);
    snprintf(q, sizeof q, "SELECT v FROM a AS OF %llu WHERE id = 1", (unsigned long long)P);
    OK(run(&s, q));
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    OK(run(&s, "UPDATE a SET v = 20 WHERE id = 2"));
    OK(run(&s, "CHECKPOINT"));
    uint64_t P2 = db->lake_seq;
    CHECK(ice_nsnaps(db, dir, "a") == 2);
    OK(run(&s, "UPDATE b SET v = 20 WHERE id = 2")); /* a commit past P2, so the horizon can pass it */
    snprintf(q, sizeof q, "COMPACT a PURGE BEFORE %llu", (unsigned long long)db->seq);
    OK(run(&s, q)); /* past P2: the head alone */
    int n = ice_nsnaps(db, dir, "a");
    if (n != 1) fprintf(stderr, "    a: %d snapshots past its horizon\n", n);
    CHECK(n == 1);
    snprintf(q, sizeof q, "SELECT v FROM a AS OF %llu WHERE id = 1", (unsigned long long)P2);
    CHECK(run(&s, q) == IMDB_ERR_HISTORY);
    CHECK(ice_verified(db) && audit_says(dir, NULL) <= 0);
    imdb_session_close(&s);
    imdb_close(db);
}

const test_case ice_tests[] = {
    {"ice_roaring", t_ice_roaring},
    {"ice_json", t_ice_json},
    {"ice_avro", t_ice_avro},
    {"ice_layer", t_ice_layer},
    {"ice_lies", t_ice_lies},
    {"ice_drop", t_ice_drop},
    {"ice_replica", t_ice_replica},
    {"ice_reads", t_ice_reads},
    {"ice_cut", t_ice_cut},
    {"ice_restore", t_ice_restore},
    {"ice_values", t_ice_values},
    {"ice_changed", t_ice_changed},
    {"ice_untouched", t_ice_untouched},
    {"ice_idle", t_ice_idle},
    {"ice_horizon", t_ice_horizon},
};
const size_t ice_ntests = sizeof ice_tests / sizeof *ice_tests;
