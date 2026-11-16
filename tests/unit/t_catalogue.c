/* P2 D1.1: backups' expiry (sealed in the prologue), the catalogue (catalogue.h: its records, a torn append cut off at
 * the next one, any other bad line refused, the lock), the erasure debt (the erasures listed against the backups made
 * before them) and the restore rule (refused, --accept-erased recording ERASE_DEBT, --reerase applying the primary's
 * commits through the last erasure). */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../src/backup.h"
#include "../../src/catalogue.h"
#include "../../src/db.h"
#include "test.h"
#include "thelp.h"

typedef struct cat_fx {
    char dir[600], p[620], k[620], cat[620], b1[620], b2[620];
    uint8_t key[IMDB_BACKUP_KEY_LEN];
    uint64_t e1;   /* the ERASE's commit, between the two backups */
    uint64_t last; /* p's last commit */
} cat_fx;

/* p: rows of subjects 42 and 7, b1 (full, catalogued, expiring in 2 days), an ERASE of 42 at e1, more rows, b2 (an
 * incremental after b1, catalogued, never expiring) */
static bool cat_make(cat_fx *x)
{
    memset(x, 0, sizeof *x);
    const char *base = test_tmpdir();
    snprintf(x->dir, sizeof x->dir, "%s", base);
    snprintf(x->p, sizeof x->p, "%s/p", base);
    snprintf(x->k, sizeof x->k, "%s/backup.key", base);
    snprintf(x->cat, sizeof x->cat, "%s/catalogue", base);
    snprintf(x->b1, sizeof x->b1, "%s/b1.bak", base);
    snprintf(x->b2, sizeof x->b2, "%s/b2.bak", base);
    uint8_t id[32];
    if (imdb_init(x->p, false, NULL, E) || imdb_backup_key_create(x->k, id, E) || imdb_backup_key_load(x->k, x->key, E))
        return false;
    imdb_db *db = open_db(x->p);
    if (!db) return false;
    int rc = make_table(db, E);
    for (int64_t i = 1; !rc && i <= 20; i++) rc = ins1(db, i, i % 4 == 0 ? 42 : 7, i, i % 4 == 0 ? "secret-42" : "plain");
    imdb_close(db);
    imdb_backup_info bi;
    imdb_backup_opts o1 = {.expires_days = 2, .catalogue = x->cat}, o2 = {.catalogue = x->cat};
    if (rc || imdb_backup_full_ex(x->p, x->b1, x->key, &o1, &bi, E)) return false;
    if (!(db = open_db(x->p))) return false;
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report er;
    rc = imdb_erase_subject(db, &subj, &er, E);
    x->e1 = db->seq;
    for (int64_t i = 21; !rc && i <= 25; i++) rc = ins1(db, i, 7, i, "after");
    x->last = db->seq;
    imdb_close(db);
    return !rc && !imdb_backup_incremental_ex(x->p, x->b1, x->b2, x->key, &o2, &bi, E);
}

/* --expires is sealed in the prologue (its hash is every chunk's additional data): read back, and a changed byte fails
 * the file; a version 1 prologue is refused by name, and one of a digest_alg 1 database (format 1 keeps 2 alone) */
static void t_catalogue_expiry(void)
{
    cat_fx x;
    CHECK(cat_make(&x));
    imdb_backup_info a, b;
    OK(imdb_backup_check(x.b1, x.key, &a, E));
    OK(imdb_backup_check(x.b2, x.key, &b, E));
    CHECK(a.made_us && a.expires_us == a.made_us + 2ull * 86400 * 1000000 && b.made_us >= a.made_us && b.expires_us == 0);
    size_t n;
    uint8_t *f = slurp(x.b1, &n);
    CHECK(f && n > IMDB_BACKUP_PROLOGUE);
    if (!f) return;
    char bad[700];
    snprintf(bad, sizeof bad, "%s/bad.bak", x.dir);
    f[208] ^= 1; /* expires_us's low byte */
    spit(bad, f, n);
    SOFT(imdb_backup_check(bad, x.key, &a, E) != 0);
    f[208] ^= 1;
    f[8] = 1; /* version 1 */
    unlink(bad);
    spit(bad, f, n);
    imdb_err_clear(E);
    SOFT(imdb_backup_check(bad, x.key, &a, E) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "format version 1"));
    f[8] = 2; /* version 2 again, its database's digest algorithm 1 (dropped before the freeze): refused by name too */
    f[32] = 1;
    unlink(bad);
    spit(bad, f, n);
    imdb_err_clear(E);
    SOFT(imdb_backup_check(bad, x.key, &a, E) == IMDB_ERR_UNSUPPORTED && strstr(g_e.msg, "digest_alg 1"));
    free(f);
}

/* the records: both backups, the erasure between them owed by b1 alone, the scan through p's last commit; forget; a
 * name listed twice and another database's backup refused; note adds what came since, once */
static void t_catalogue_records(void)
{
    cat_fx x;
    CHECK(cat_make(&x));
    imdb_catalogue c;
    OK(imdb_catalogue_read(x.cat, &c, E));
    SOFT(c.has_head && c.nb == 2 && c.ne == 1 && c.er[0].seq == x.e1 && c.scanned == x.last && !c.torn && !c.gap_to);
    if (c.nb == 2) {
        SOFT(strcmp(c.b[0].name, x.b1) == 0 && !c.b[0].incremental && c.b[0].last < x.e1 && c.b[0].expires_us);
        SOFT(strcmp(c.b[1].name, x.b2) == 0 && c.b[1].incremental && c.b[1].last == x.last && !c.b[1].expires_us);
    }
    imdb_catalogue_free(&c);
    imdb_backup_info bi;
    OK(imdb_backup_check(x.b1, x.key, &bi, E));
    imdb_err_clear(E);
    SOFT(imdb_catalogue_add_backup(x.cat, x.b1, &bi, x.p, E) == IMDB_ERR_STATE); /* listed already */
    char q[700];
    snprintf(q, sizeof q, "%s/q", x.dir);
    SOFT(imdb_init(q, false, NULL, E) == 0);
    imdb_db *db = open_db(q);
    SOFT(db && make_table(db, E) == 0);
    imdb_close(db);
    imdb_backup_info qi = bi;
    SOFT(imdb_identity_read(q, &qi.id, &(bool){false}, E) == 0);
    imdb_err_clear(E);
    SOFT(imdb_catalogue_add_backup(x.cat, "q.bak", &qi, q, E) == IMDB_ERR_INVALID); /* another database */
    /* two more erasures on p: note lists them, once */
    db = open_db(x.p);
    CHECK(db);
    imdb_value s7 = {.type = IMDB_T_INT64, .i = 7};
    imdb_erase_report er;
    SOFT(imdb_erase_subject(db, &s7, &er, E) == 0);
    uint64_t e2 = db->seq;
    SOFT(ins1(db, 40, 9, 40, "x") == 0);
    imdb_value s9 = {.type = IMDB_T_INT64, .i = 9};
    SOFT(imdb_erase_subject(db, &s9, &er, E) == 0);
    uint64_t e3 = db->seq;
    imdb_close(db);
    uint64_t added = 9;
    SOFT(imdb_catalogue_note(x.cat, x.p, &added, E) == 0 && added == 2);
    SOFT(imdb_catalogue_note(x.cat, x.p, &added, E) == 0 && added == 0);
    SOFT(imdb_catalogue_forget(x.cat, x.b1, E) == 0);
    imdb_err_clear(E);
    SOFT(imdb_catalogue_forget(x.cat, x.b1, E) == IMDB_ERR_NOTFOUND);
    OK(imdb_catalogue_read(x.cat, &c, E));
    SOFT(c.ne == 3 && c.er[1].seq == e2 && c.er[2].seq == e3 && c.scanned == e3 && c.nb == 2 && c.b[0].forgotten &&
         !c.b[1].forgotten);
    imdb_catalogue_free(&c);
}

/* a torn last line (no newline: an append a crash cut short) is ignored, then cut off by the next append; a complete
 * line with a wrong CRC, or with a good CRC but a field out of form, refuses the file; the lock refuses a second user */
static void t_catalogue_torn(void)
{
    cat_fx x;
    CHECK(cat_make(&x));
    size_t n0;
    uint8_t *f0 = slurp(x.cat, &n0);
    CHECK(f0 && n0);
    int fd = open(x.cat, O_WRONLY | O_APPEND);
    CHECK(fd >= 0);
    SOFT(write(fd, "erase 99", 8) == 8);
    close(fd);
    imdb_catalogue c;
    OK(imdb_catalogue_read(x.cat, &c, E));
    SOFT(c.torn && c.whole == n0 && c.nb == 2 && c.ne == 1);
    imdb_catalogue_free(&c);
    uint64_t added;
    OK(imdb_catalogue_note(x.cat, x.p, &added, E)); /* an append: the torn tail goes first */
    size_t n1;
    uint8_t *f1 = slurp(x.cat, &n1);
    SOFT(f1 && n1 == n0 && memcmp(f0, f1, n0) == 0); /* nothing new to note: exactly the file before the torn bytes */
    free(f1);
    OK(imdb_catalogue_read(x.cat, &c, E));
    SOFT(!c.torn && c.nb == 2);
    imdb_catalogue_free(&c);
    /* a complete line damaged: the second line's last hex digit of its CRC */
    char bad[700];
    snprintf(bad, sizeof bad, "%s/bad.cat", x.dir);
    uint8_t *nl = memchr(f0, '\n', n0), *nl2 = nl ? memchr(nl + 1, '\n', n0 - (size_t)(nl + 1 - f0)) : NULL;
    SOFT(nl2 != NULL);
    if (nl2) {
        nl2[-1] = nl2[-1] == '0' ? '1' : '0';
        spit(bad, f0, n0);
        imdb_err_clear(E);
        SOFT(imdb_catalogue_read(bad, &c, E) == IMDB_ERR_CORRUPT && strstr(g_e.msg, "line 2"));
        nl2[-1] = nl2[-1] == '0' ? '1' : '0';
    }
    /* a good CRC over a field out of form (a leading zero) */
    char line[160], rec[120];
    snprintf(rec, sizeof rec, "erase 0%llu 5", (unsigned long long)(x.last + 7));
    snprintf(line, sizeof line, "%s %08x\n", rec, imdb_crc32c_ref(0, rec, strlen(rec)));
    unlink(bad);
    spit(bad, f0, n0);
    fd = open(bad, O_WRONLY | O_APPEND);
    SOFT(fd >= 0 && write(fd, line, strlen(line)) == (ssize_t)strlen(line));
    if (fd >= 0) close(fd);
    imdb_err_clear(E);
    SOFT(imdb_catalogue_read(bad, &c, E) == IMDB_ERR_CORRUPT);
    /* the lock: held by another, an append refused */
    fd = open(x.cat, O_RDONLY);
    SOFT(fd >= 0 && flock(fd, LOCK_EX) == 0);
    imdb_err_clear(E);
    SOFT(imdb_catalogue_note(x.cat, x.p, &added, E) == IMDB_ERR_STATE && strstr(g_e.msg, "is held"));
    if (fd >= 0) close(fd);
    free(f0);
}

/* the restore rule: b1 predates the erasure at e1, so restoring it with the catalogue is refused (no destination left);
 * --accept-erased restores it and records the debt; --reerase applies p's commits through e1 (the copy then at e1, the
 * erased subject gone, p's hash there); no source: the debt unknown; --reerase with --until refused; b2 owes nothing */
static void t_catalogue_restore(void)
{
    cat_fx x;
    CHECK(cat_make(&x));
    const char *files[1] = {x.b1};
    char r[700], debt[760];
    imdb_backup_info ri;
    snprintf(r, sizeof r, "%s/r", x.dir);
    imdb_restore_opts ro = {.catalogue = x.cat};
    imdb_err_clear(E);
    SOFT(imdb_restore_ex(r, x.key, files, 1, &ro, &ri, E) == IMDB_ERR_STATE && strstr(g_e.msg, "before the erasure"));
    SOFT(access(r, F_OK) != 0);
    ro.accept_erased = true;
    SOFT(imdb_restore_ex(r, x.key, files, 1, &ro, &ri, E) == 0 && ri.debt_recorded && !ri.reerased && ri.erasures == 1 &&
         ri.last_erasure == x.e1 && !ri.debt_unknown);
    snprintf(debt, sizeof debt, "%s/ERASE_DEBT", r);
    size_t n;
    uint8_t *d = slurp(debt, &n);
    char want[64];
    snprintf(want, sizeof want, "\nerase %llu ", (unsigned long long)x.e1);
    SOFT(d && n > 21 && memcmp(d, "imagedb-erase-debt 1\n", 21) == 0 && mem_contains(d, n, want + 1));
    free(d);
    imdb_db *db = open_db(r);
    SOFT(db && count_subject(db, 42, db->seq) > 0); /* it does hold them: the debt */
    imdb_close(db);
    char r2[700];
    snprintf(r2, sizeof r2, "%s/r2", x.dir);
    imdb_restore_opts rr = {.reerase = x.p};
    SOFT(imdb_restore_ex(r2, x.key, files, 1, &rr, &ri, E) == 0 && ri.reerased && ri.last_erasure == x.e1 &&
         ri.last_seq == x.e1);
    db = open_db(r2);
    imdb_db *pdb = NULL;
    imdb_open_opts po = {.sync = 0, .read_only = true};
    SOFT(db && imdb_open(x.p, &po, &pdb, E) == 0);
    if (db && pdb) {
        const imdb_commit_info *ci = imdb_ci_at(pdb, x.e1, E);
        SOFT(db->seq == x.e1 && ci && memcmp(db->head, ci->hash, 32) == 0 && count_subject(db, 42, db->seq) == 0);
    }
    imdb_close(pdb);
    imdb_close(db);
    char r3[700];
    snprintf(r3, sizeof r3, "%s/r3", x.dir);
    SOFT(imdb_restore_ex(r3, x.key, files, 1, NULL, &ri, E) == 0 && ri.debt_unknown && !ri.erasures);
    imdb_restore_opts ru = {.reerase = x.p, .until_seq = 1};
    imdb_err_clear(E);
    SOFT(imdb_restore_ex(r3, x.key, files, 1, &ru, &ri, E) == IMDB_ERR_INVALID);
    const char *both[2] = {x.b1, x.b2};
    char r4[700];
    snprintf(r4, sizeof r4, "%s/r4", x.dir);
    imdb_restore_opts rc4 = {.catalogue = x.cat};
    SOFT(imdb_restore_ex(r4, x.key, both, 2, &rc4, &ri, E) == 0 && !ri.erasures && !ri.debt_unknown &&
         ri.last_seq == x.last);
}

const test_case catalogue_tests[] = {
    {"catalogue_expiry", t_catalogue_expiry},
    {"catalogue_records", t_catalogue_records},
    {"catalogue_torn", t_catalogue_torn},
    {"catalogue_restore", t_catalogue_restore},
};
const size_t catalogue_ntests = sizeof catalogue_tests / sizeof *catalogue_tests;
