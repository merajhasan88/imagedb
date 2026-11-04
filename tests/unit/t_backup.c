/* Encrypted backups (src/backup.c): the cipher against OpenSSL, the key file, round trips (from commit 1, and a
 * seed past a log cut), every byte of a file damaged, truncation, another key, the test restore. */
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../src/backup.h"
#include "../../src/db.h"
#include "../../src/sql.h"
#include "../../src/writer.h"
#include "../../src/vendor/monocypher/monocypher.h"
#include "test.h"
#include "thelp.h"

static int audit_ok(const char *dir);

/* ---- XChaCha20-Poly1305 (Monocypher's crypto_aead_lock) against OpenSSL ------------------------- */

/* HChaCha20 from OpenSSL's ChaCha20: the first block under IV = the 16 input bytes (counter word and nonce) is the
 * 20-round state plus the input state; HChaCha20 is the state's words 0-3 and 12-15 before that addition. */
static int hchacha20_ossl(const uint8_t key[32], const uint8_t in[16], uint8_t out[32])
{
    uint8_t zero[64] = {0}, ks[64];
    int len = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int ok = c && EVP_EncryptInit_ex(c, EVP_chacha20(), NULL, key, in) == 1 &&
             EVP_EncryptUpdate(c, ks, &len, zero, 64) == 1 && len == 64;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return -1;
    static const uint32_t sigma[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
    for (int i = 0; i < 4; i++) {
        imdb_le32(out + 4 * i, imdb_get_le32(ks + 4 * i) - sigma[i]);
        imdb_le32(out + 16 + 4 * i, imdb_get_le32(ks + 48 + 4 * i) - imdb_get_le32(in + 4 * i));
    }
    return 0;
}

/* XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha): ChaCha20-Poly1305 (RFC 8439) under HChaCha20(key, nonce[0..16]) and
 * the nonce 0^4 || nonce[16..24]. */
static int xchacha_ossl(const uint8_t key[32], const uint8_t nonce[24], const uint8_t *ad, size_t adn,
                        const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[16])
{
    uint8_t sub[32], iv[12] = {0};
    if (hchacha20_ossl(key, nonce, sub)) return -1;
    memcpy(iv + 4, nonce + 16, 8);
    int len = 0, ok;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    ok = c && EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), NULL, sub, iv) == 1 &&
         (adn == 0 || EVP_EncryptUpdate(c, NULL, &len, ad, (int)adn) == 1) &&
         (n == 0 || (EVP_EncryptUpdate(c, ct, &len, pt, (int)n) == 1 && (size_t)len == n)) &&
         EVP_EncryptFinal_ex(c, ct + n, &len) == 1 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

static void t_backup_xchacha_openssl(void)
{
    static const size_t sizes[] = {0, 1, 15, 16, 63, 64, 65, 1000, 4096, 70000};
    for (size_t si = 0; si < sizeof sizes / sizeof sizes[0]; si++) {
        size_t n = sizes[si];
        uint8_t key[32], nonce[24], ad[45], tag[16], tag2[16];
        uint8_t *pt = malloc(n + 1), *ct = malloc(n + 1), *ct2 = malloc(n + 1), *back = malloc(n + 1);
        CHECK(pt && ct && ct2 && back);
        test_rand_bytes(key, sizeof key);
        test_rand_bytes(nonce, sizeof nonce);
        test_rand_bytes(ad, sizeof ad);
        test_rand_bytes(pt, n);
        crypto_aead_lock(ct, tag, key, nonce, ad, sizeof ad, pt, n);
        CHECK(xchacha_ossl(key, nonce, ad, sizeof ad, pt, n, ct2, tag2) == 0);
        CHECK(memcmp(ct, ct2, n) == 0 && memcmp(tag, tag2, 16) == 0);
        CHECK(crypto_aead_unlock(back, tag, key, nonce, ad, sizeof ad, ct, n) == 0 && memcmp(back, pt, n) == 0);
        /* any one bit of the tag, the additional data or the ciphertext: refused */
        tag[test_rand() % 16] ^= (uint8_t)(1u << (test_rand() % 8));
        CHECK(crypto_aead_unlock(back, tag, key, nonce, ad, sizeof ad, ct, n) != 0);
        memcpy(tag, tag2, 16);
        ad[test_rand() % sizeof ad] ^= 1;
        CHECK(crypto_aead_unlock(back, tag, key, nonce, ad, sizeof ad, ct, n) != 0);
        free(pt);
        free(ct);
        free(ct2);
        free(back);
    }
}

/* ---- the key file ------------------------------------------------------------------------------------ */

static void t_backup_key_file(void)
{
    const char *tmp = test_tmpdir();
    char kf[600], ln[600], bad[600];
    snprintf(kf, sizeof kf, "%s/backup.key", tmp);
    snprintf(ln, sizeof ln, "%s/link.key", tmp);
    snprintf(bad, sizeof bad, "%s/short.key", tmp);
    uint8_t id[32], id2[32], key[IMDB_BACKUP_KEY_LEN];
    OK(imdb_backup_key_create(kf, id, E));
    struct stat st;
    CHECK(stat(kf, &st) == 0 && (st.st_mode & 0777) == 0400 && st.st_size == IMDB_BACKUP_KEY_LEN);
    CHECK(imdb_backup_key_create(kf, id2, E) != 0); /* never replaced */
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_key_id(key, id2);
    CHECK(memcmp(id, id2, 32) == 0);
    CHECK(symlink(kf, ln) == 0);
    CHECK(imdb_backup_key_load(ln, key, E) != 0); /* not through a symlink */
    uint8_t b[33] = {0};
    spit(bad, b, 31);
    CHECK(imdb_backup_key_load(bad, key, E) != 0);
    unlink(bad);
    spit(bad, b, 33);
    CHECK(imdb_backup_key_load(bad, key, E) != 0);
}

/* ---- round trips --------------------------------------------------------------------------------------- */

/* A primary with a root key: a table, rows, updates and deletes, a CHECKPOINT, an ERASE SUBJECT (42's rows), rows
 * after it. Returns its last commit and head. */
static int make_source(const char *p, const uint8_t root_pk[IMDB_PUBKEY_LEN], uint64_t *seq, uint8_t head[32])
{
    if (imdb_init_primary(p, root_pk, E)) return -1;
    imdb_db *db = open_db(p);
    if (!db) return -1;
    int rc = make_table(db, E);
    for (int64_t i = 1; !rc && i <= 300; i++) rc = ins1(db, i, i % 7 == 0 ? 42 : i % 5, i * 10, i % 7 == 0 ? "secret-42" : "plain");
    if (!rc) rc = imdb_checkpoint(db, E);
    imdb_value subj = {.type = IMDB_T_INT64, .i = 42};
    imdb_erase_report rep;
    if (!rc) rc = imdb_erase_subject(db, &subj, &rep, E);
    for (int64_t i = 301; !rc && i <= 320; i++) rc = ins1(db, i, 3, i, "after");
    *seq = db->seq;
    memcpy(head, db->head, 32);
    imdb_close(db);
    return rc;
}

static void t_backup_roundtrip(void)
{
    const char *tmp = test_tmpdir();
    char p[600], out[600], r[600], kf[600], k2[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(out, sizeof out, "%s/full.bak", tmp);
    snprintf(r, sizeof r, "%s/restored", tmp);
    snprintf(kf, sizeof kf, "%s/backup.key", tmp);
    snprintf(k2, sizeof k2, "%s/other.key", tmp);
    uint8_t root_seed[IMDB_SEED_LEN], key[IMDB_BACKUP_KEY_LEN], other[IMDB_BACKUP_KEY_LEN], id[32], head[32];
    test_rand_bytes(root_seed, sizeof root_seed);
    imdb_signer root;
    imdb_signer_init(&root, root_seed);
    uint64_t seq = 0;
    CHECK(make_source(p, root.pk, &seq, head) == 0);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    OK(imdb_backup_key_create(k2, id, E));
    OK(imdb_backup_key_load(k2, other, E));
    imdb_backup_info bi, ci, ri;
    OK(imdb_backup_full(p, out, key, &bi, E));
    /* a snapshot (the source has published one): its seed, then the commits after it */
    CHECK(bi.parts == 2 && bi.seed_seq && bi.seed_seq < seq && bi.first_seq == bi.seed_seq && bi.last_seq == seq &&
          memcmp(bi.last_hash, head, 32) == 0);
    CHECK(imdb_backup_full(p, out, key, &ci, E) == IMDB_ERR_STATE); /* never over an existing file */
    /* sealed: nothing of a row or a frame in the clear */
    size_t n = 0;
    uint8_t *b = slurp(out, &n);
    CHECK(b && n > IMDB_BACKUP_PROLOGUE && !mem_contains(b, n, "plain") && !mem_contains(b, n, "after"));
    free(b);
    OK(imdb_backup_check(out, key, &ci, E));
    CHECK(ci.last_seq == seq && ci.chunks == bi.chunks && ci.payload_bytes == bi.payload_bytes);
    CHECK(imdb_backup_check(out, other, &ci, E) == IMDB_ERR_AUTH); /* another key: named, not a tag failure */
    const char *files[1] = {out};
    OK(imdb_restore(r, key, files, 1, &ri, E));
    CHECK(ri.last_seq == seq);
    CHECK(imdb_restore(r, key, files, 1, &ri, E) == IMDB_ERR_STATE); /* the destination exists */
    /* the copy is a replica seeded at S: the same database, chain position, schemas, horizons and rows (view token) */
    uint8_t vt_p[32], vt_r[32];
    imdb_open_opts ro = {.sync = 1, .read_only = true};
    imdb_db *src = NULL;
    OK(imdb_open(p, &ro, &src, E));
    OK(imdb_view_token(src, vt_p, E));
    imdb_db *db = open_db(r);
    CHECK(db && db->replica && db->seq == seq && memcmp(db->head, head, 32) == 0 && db->log_floor == bi.seed_seq);
    OK(imdb_view_token(db, vt_r, E));
    CHECK(memcmp(vt_p, vt_r, 32) == 0);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    /* VERIFY begins at the copy's floor: the seed checked against S's signed digest, then each commit after it */
    CHECK(vr.floor == bi.seed_seq && vr.commits == seq - bi.seed_seq && vr.sigs_checked == seq - bi.seed_seq && vr.seeded);
    /* the copy's history begins at S (its contract, README "Backup and restore"): AS OF below it is refused there,
     * where the source, holding its whole log, still answers */
    char q[96];
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM txns AS OF %llu", (unsigned long long)(bi.seed_seq - 1));
    for (int w = 0; w < 2; w++) {
        imdb_session s;
        imdb_session_init(&s, w ? db : src);
        imdb_result res;
        memset(&res, 0, sizeof res);
        imdb_err_clear(E);
        int rq = imdb_exec_one(&s, q, strlen(q), NULL, 0, &res, E);
        imdb_result_free(&res);
        imdb_session_close(&s);
        CHECK(w ? rq == IMDB_ERR_NOTFOUND : rq == 0);
    }
    imdb_close(src);
    imdb_close(db);
    CHECK(audit_ok(r)); /* the independent verifier accepts the copy restored from the encrypted snapshot */
    /* writable by promotion with the root key, as a replica is */
    imdb_promote_opts po = {.old_writer_stopped = true};
    imdb_promote_result pr;
    OK(imdb_promote(r, root_seed, &po, &pr, E));
    db = open_db(r);
    CHECK(db && !db->replica);
    OK(ins1(db, 1000, 9, 1, "new writer"));
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    imdb_signer_wipe(&root);
}

static int audit_ok(const char *dir) /* 1: no auditor in this build (IMDB_AUDIT_BIN) */
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 1;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' >/dev/null 2>&1", bin, dir);
    return system(cmd) == 0;
}

/* A backup taken right after a CHECKPOINT, nothing after it: its second part is empty, its last commit is the seed's
 * own, whose hash comes from the seed (the publish's commit ends its log segment); the copy's head is that hash. */
static void t_backup_at_snapshot(void)
{
    const char *tmp = test_tmpdir();
    char p[600], out[600], r[600], kf[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(out, sizeof out, "%s/full.bak", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    snprintf(kf, sizeof kf, "%s/k", tmp);
    uint8_t key[IMDB_BACKUP_KEY_LEN], id[32], head[32], vt_p[32], vt_r[32];
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    for (int64_t i = 1; i <= 30; i++) OK(ins1(db, i, i % 4, i, "row"));
    OK(imdb_checkpoint(db, E));
    uint64_t seq = db->seq;
    memcpy(head, db->head, 32);
    CHECK(db->lake_seq == seq); /* the latest commit is the publish */
    OK(imdb_view_token(db, vt_p, E));
    imdb_close(db);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info bi;
    OK(imdb_backup_full(p, out, key, &bi, E));
    CHECK(bi.parts == 2 && bi.seed_seq == seq && bi.first_seq == seq && bi.last_seq == seq &&
          memcmp(bi.last_hash, head, 32) == 0);
    const char *files[1] = {out};
    OK(imdb_restore(r, key, files, 1, &bi, E));
    db = open_db(r);
    CHECK(db && db->seq == seq && memcmp(db->head, head, 32) == 0 && db->log_floor == seq);
    OK(imdb_view_token(db, vt_r, E));
    CHECK(memcmp(vt_p, vt_r, 32) == 0);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    CHECK(vr.floor == seq && vr.commits == 0);
    imdb_close(db);
    CHECK(audit_ok(r));
}

/* A database that never published a snapshot: its backup is its frames from commit 1, and the copy holds the whole
 * log, the source's frame for frame (AS OF anywhere in it, VERIFY from the genesis). */
static void t_backup_whole_log(void)
{
    const char *tmp = test_tmpdir();
    char p[600], out[600], r[600], kf[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(out, sizeof out, "%s/full.bak", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    snprintf(kf, sizeof kf, "%s/k", tmp);
    uint8_t key[IMDB_BACKUP_KEY_LEN], id[32];
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    for (int64_t i = 1; i <= 40; i++) OK(ins1(db, i, i % 3, i, "row"));
    uint64_t seq = db->seq;
    CHECK(db->lake_seq == 0); /* nothing published */
    imdb_close(db);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info bi;
    OK(imdb_backup_full(p, out, key, &bi, E));
    CHECK(bi.parts == 1 && !bi.seed_seq && bi.first_seq == 1 && bi.last_seq == seq);
    const char *files[1] = {out};
    OK(imdb_restore(r, key, files, 1, &bi, E));
    char why[256];
    char la[700], lb[700];
    snprintf(la, sizeof la, "%s/log", p);
    snprintf(lb, sizeof lb, "%s/log", r);
    CHECK(logs_identical(la, lb, why, sizeof why)); /* the source's frames, byte for byte */
    db = open_db(r);
    CHECK(db && db->seq == seq && db->log_floor == 0);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    CHECK(vr.floor == 0 && vr.commits == seq);
    imdb_close(db);
}

/* An empty database's backup restores to an empty copy. */
static void t_backup_empty(void)
{
    const char *tmp = test_tmpdir();
    char p[600], out[600], r[600], kf[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(out, sizeof out, "%s/empty.bak", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    snprintf(kf, sizeof kf, "%s/k", tmp);
    uint8_t key[IMDB_BACKUP_KEY_LEN], id[32];
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p); /* a writable open publishes DURABLE: ship needs it */
    CHECK(db);
    imdb_close(db);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info bi;
    OK(imdb_backup_full(p, out, key, &bi, E));
    CHECK(bi.parts == 1 && bi.last_seq == 0 && bi.first_seq == 0);
    const char *files[1] = {out};
    OK(imdb_restore(r, key, files, 1, &bi, E));
    db = open_db(r);
    CHECK(db && db->seq == 0);
    imdb_close(db);
}

/* Every byte of a small backup flipped, every truncation, a byte appended: each refused by the check, and so by
 * restore (which checks every file whole before it applies anything). */
static void t_backup_damage(void)
{
    const char *tmp = test_tmpdir();
    char p[600], out[600], bad[600], kf[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(out, sizeof out, "%s/small.bak", tmp);
    snprintf(bad, sizeof bad, "%s/bad.bak", tmp);
    snprintf(kf, sizeof kf, "%s/k", tmp);
    uint8_t key[IMDB_BACKUP_KEY_LEN], id[32];
    OK(imdb_init(p, false, NULL, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    OK(make_table(db, E));
    OK(ins1(db, 1, 1, 10, "a"));
    OK(ins1(db, 2, 2, 20, "b"));
    imdb_close(db);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info bi;
    OK(imdb_backup_full(p, out, key, &bi, E));
    size_t n = 0;
    uint8_t *b = slurp(out, &n);
    CHECK(b && n > IMDB_BACKUP_PROLOGUE + 2 * (IMDB_BACKUP_CHUNK_HDR + IMDB_BACKUP_TAG));
    for (size_t i = 0; i < n; i++) {
        b[i] ^= (uint8_t)(1u << (i % 8));
        unlink(bad);
        spit(bad, b, n);
        if (imdb_backup_check(bad, key, &bi, E) == 0) {
            char m[96];
            snprintf(m, sizeof m, "a flipped byte at %zu passed the check", i);
            test_fail(__FILE__, __LINE__, m);
            free(b);
            return;
        }
        b[i] ^= (uint8_t)(1u << (i % 8));
    }
    for (size_t len = 0; len < n; len++) {
        unlink(bad);
        spit(bad, b, len);
        if (imdb_backup_check(bad, key, &bi, E) == 0) {
            char m[96];
            snprintf(m, sizeof m, "a file cut at %zu of %zu passed the check", len, n);
            test_fail(__FILE__, __LINE__, m);
            free(b);
            return;
        }
    }
    uint8_t *x = malloc(n + 1);
    CHECK(x);
    memcpy(x, b, n);
    x[n] = 0;
    unlink(bad);
    spit(bad, x, n + 1);
    CHECK(imdb_backup_check(bad, key, &bi, E) != 0);
    free(x);
    /* the intact file still passes, and restore refuses a damaged one before touching the destination */
    OK(imdb_backup_check(out, key, &bi, E));
    b[IMDB_BACKUP_PROLOGUE + IMDB_BACKUP_CHUNK_HDR] ^= 1;
    unlink(bad);
    spit(bad, b, n);
    char r[600];
    snprintf(r, sizeof r, "%s/r", tmp);
    const char *files[1] = {bad};
    CHECK(imdb_restore(r, key, files, 1, &bi, E) != 0);
    CHECK(access(r, F_OK) != 0);
    free(b);
}

/* The chunks of a backup (a snapshot: the seed's part, the frames' part, the summary) moved, dropped, repeated, or one
 * taken from another backup of the same database under the same key: each refused, its place in its file being
 * bound into its tag. */
static size_t chunk_at(const uint8_t *b, size_t n, size_t off, size_t *len)
{
    if (off + IMDB_BACKUP_CHUNK_HDR > n) return 0;
    *len = IMDB_BACKUP_CHUNK_HDR + (size_t)imdb_get_le32(b + off) + IMDB_BACKUP_TAG;
    return off + *len <= n ? 1 : 0;
}

static void t_backup_chunks_moved(void)
{
    const char *tmp = test_tmpdir();
    char p[600], o1[600], o2[600], bad[600], kf[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(o1, sizeof o1, "%s/one.bak", tmp);
    snprintf(o2, sizeof o2, "%s/two.bak", tmp);
    snprintf(bad, sizeof bad, "%s/bad.bak", tmp);
    snprintf(kf, sizeof kf, "%s/k", tmp);
    uint8_t root_seed[IMDB_SEED_LEN], key[IMDB_BACKUP_KEY_LEN], id[32], head[32];
    test_rand_bytes(root_seed, sizeof root_seed);
    imdb_signer root;
    imdb_signer_init(&root, root_seed);
    uint64_t seq = 0;
    CHECK(make_source(p, root.pk, &seq, head) == 0);
    imdb_signer_wipe(&root);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info bi;
    OK(imdb_backup_full(p, o1, key, &bi, E));
    OK(imdb_backup_full(p, o2, key, &bi, E)); /* the same database and commits, another nonce prefix */
    CHECK(bi.parts == 2 && bi.chunks == 2);   /* small: the seed's part, the frames' part, then the summary */
    size_t n1 = 0, n2 = 0;
    uint8_t *a = slurp(o1, &n1), *z = slurp(o2, &n2);
    CHECK(a && z);
    size_t c0 = IMDB_BACKUP_PROLOGUE, l0 = 0, l1 = 0, l2 = 0, z0 = 0, z1 = 0;
    CHECK(chunk_at(a, n1, c0, &l0) && chunk_at(a, n1, c0 + l0, &l1) && chunk_at(a, n1, c0 + l0 + l1, &l2) &&
          c0 + l0 + l1 + l2 == n1);
    CHECK(chunk_at(z, n2, c0, &z0) && chunk_at(z, n2, c0 + z0, &z1));
    uint8_t *x = malloc(n1 + n2);
    CHECK(x);
    /* the first two swapped */
    memcpy(x, a, c0);
    memcpy(x + c0, a + c0 + l0, l1);
    memcpy(x + c0 + l1, a + c0, l0);
    memcpy(x + c0 + l1 + l0, a + c0 + l0 + l1, l2);
    unlink(bad);
    spit(bad, x, n1);
    CHECK(imdb_backup_check(bad, key, &bi, E) != 0);
    /* the middle one dropped */
    memcpy(x, a, c0 + l0);
    memcpy(x + c0 + l0, a + c0 + l0 + l1, l2);
    unlink(bad);
    spit(bad, x, n1 - l1);
    CHECK(imdb_backup_check(bad, key, &bi, E) != 0);
    /* the first one repeated */
    memcpy(x, a, c0 + l0);
    memcpy(x + c0 + l0, a + c0, n1 - c0);
    unlink(bad);
    spit(bad, x, n1 + l0);
    CHECK(imdb_backup_check(bad, key, &bi, E) != 0);
    /* the second one taken from the other backup (same key, same database, same commits) */
    memcpy(x, a, c0 + l0);
    memcpy(x + c0 + l0, z + c0 + z0, z1);
    memcpy(x + c0 + l0 + z1, a + c0 + l0 + l1, l2);
    unlink(bad);
    spit(bad, x, c0 + l0 + z1 + l2);
    CHECK(imdb_backup_check(bad, key, &bi, E) != 0);
    free(x);
    free(a);
    free(z);
}

/* The test restore: VERIFY on a copy that is gone afterwards. */
static void t_backup_verify(void)
{
    const char *tmp = test_tmpdir();
    char p[600], out[600], kf[600], scratch[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(out, sizeof out, "%s/full.bak", tmp);
    snprintf(kf, sizeof kf, "%s/k", tmp);
    snprintf(scratch, sizeof scratch, "%s/scratch", tmp);
    CHECK(mkdir(scratch, 0700) == 0);
    uint8_t root_seed[IMDB_SEED_LEN], key[IMDB_BACKUP_KEY_LEN], id[32], head[32];
    test_rand_bytes(root_seed, sizeof root_seed);
    imdb_signer root;
    imdb_signer_init(&root, root_seed);
    uint64_t seq = 0;
    CHECK(make_source(p, root.pk, &seq, head) == 0);
    imdb_signer_wipe(&root);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info bi;
    OK(imdb_backup_full(p, out, key, &bi, E));
    imdb_verify_report vr;
    const char *files[1] = {out};
    OK(imdb_backup_verify(scratch, key, files, 1, &bi, &vr, E));
    CHECK(bi.last_seq == seq && bi.seed_seq && vr.floor == bi.seed_seq && vr.commits == seq - bi.seed_seq);
    CHECK(count_files(scratch, "") == 0); /* the copy removed */
}


/* ---- slice 2: incrementals and point in time -------------------------------------------------------------------- */

/* A full backup and two incrementals, each the commits after the one before's last: restored as a chain, the copy is
 * the source at its last commit (the view token), VERIFY and the auditor pass it. Refused: an incremental with nothing
 * new (no file left), one after a backup of another database, and a restore with a gap in the chain. */
static void t_backup_incremental(void)
{
    const char *tmp = test_tmpdir();
    char p[600], q[600], kf[600], f0[600], f1[600], f2[600], fx[600], fo[600], r[600], rg[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(q, sizeof q, "%s/q", tmp);
    snprintf(kf, sizeof kf, "%s/backup.key", tmp);
    snprintf(f0, sizeof f0, "%s/full.bak", tmp);
    snprintf(f1, sizeof f1, "%s/inc1.bak", tmp);
    snprintf(f2, sizeof f2, "%s/inc2.bak", tmp);
    snprintf(fx, sizeof fx, "%s/empty.bak", tmp);
    snprintf(fo, sizeof fo, "%s/other.bak", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    snprintf(rg, sizeof rg, "%s/rg", tmp);
    uint8_t root_seed[IMDB_SEED_LEN], key[IMDB_BACKUP_KEY_LEN], id[32], head[32];
    test_rand_bytes(root_seed, sizeof root_seed);
    imdb_signer root;
    imdb_signer_init(&root, root_seed);
    uint64_t seq = 0;
    CHECK(make_source(p, root.pk, &seq, head) == 0);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info b0, b1, b2, bx, ri;
    OK(imdb_backup_full(p, f0, key, &b0, E));
    CHECK(imdb_backup_incremental(p, f0, fx, key, &bx, E) == IMDB_ERR_STATE && access(fx, F_OK) != 0); /* nothing new */
    imdb_db *db = open_db(p);
    CHECK(db);
    if (!db) return;
    for (int64_t i = 1000; i < 1010; i++) OK(ins1(db, i, 1, i, "inc one"));
    imdb_close(db);
    OK(imdb_backup_incremental(p, f0, f1, key, &b1, E));
    CHECK(b1.incremental && b1.prev_seq == b0.last_seq && b1.first_seq == b0.last_seq + 1 && b1.last_seq == b0.last_seq + 10);
    db = open_db(p);
    CHECK(db);
    if (!db) return;
    OK(imdb_checkpoint(db, E)); /* a publish inside an incremental's commits */
    for (int64_t i = 2000; i < 2005; i++) OK(ins1(db, i, 2, i, "inc two"));
    uint8_t vt_p[32], vt_r[32];
    OK(imdb_view_token(db, vt_p, E));
    uint64_t last = db->seq;
    imdb_close(db);
    OK(imdb_backup_incremental(p, f1, f2, key, &b2, E));
    CHECK(b2.prev_seq == b1.last_seq && b2.last_seq == last);
    /* another database's full backup as the previous one: refused */
    CHECK(make_source(q, root.pk, &seq, head) == 0);
    OK(imdb_backup_full(q, fo, key, &bx, E));
    CHECK(imdb_backup_incremental(p, fo, fx, key, &bx, E) == IMDB_ERR_INVALID && access(fx, F_OK) != 0);
    /* a gap: the second incremental without the first */
    const char *gap[2] = {f0, f2};
    CHECK(imdb_restore(rg, key, gap, 2, &ri, E) == IMDB_ERR_INVALID && access(rg, F_OK) != 0);
    const char *chain[3] = {f0, f1, f2};
    OK(imdb_restore(r, key, chain, 3, &ri, E));
    CHECK(ri.last_seq == last);
    db = open_db(r);
    CHECK(db && db->seq == last);
    if (!db) return;
    OK(imdb_view_token(db, vt_r, E));
    CHECK(!memcmp(vt_p, vt_r, 32));
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
    CHECK(audit_ok(r));
}

/* Point in time: restored through each commit the chain holds, from the full backup's snapshot to the last, the copy
 * ends at that commit with the source's hash for it (the chain and the state checked on the way); by time, the last
 * commit made at or before it (a commit's own time, and a microsecond before it); outside the chain refused, and
 * nothing left behind */
static void t_backup_point_in_time(void)
{
    const char *tmp = test_tmpdir();
    char p[600], kf[600], f0[600], f1[600], r[640];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(kf, sizeof kf, "%s/backup.key", tmp);
    snprintf(f0, sizeof f0, "%s/full.bak", tmp);
    snprintf(f1, sizeof f1, "%s/inc.bak", tmp);
    uint8_t root_seed[IMDB_SEED_LEN], key[IMDB_BACKUP_KEY_LEN], id[32], head[32];
    test_rand_bytes(root_seed, sizeof root_seed);
    imdb_signer root;
    imdb_signer_init(&root, root_seed);
    uint64_t seq = 0;
    CHECK(make_source(p, root.pk, &seq, head) == 0);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    imdb_backup_info b0, b1, ri;
    OK(imdb_backup_full(p, f0, key, &b0, E));
    imdb_db *db = open_db(p);
    CHECK(db);
    if (!db) return;
    for (int64_t i = 1000; i < 1006; i++) OK(ins1(db, i, 1, i, "later"));
    imdb_close(db);
    OK(imdb_backup_incremental(p, f0, f1, key, &b1, E));
    imdb_open_opts ro = {.sync = 0, .read_only = true};
    imdb_db *src = NULL;
    OK(imdb_open(p, &ro, &src, E));
    const char *chain[2] = {f0, f1};
    for (uint64_t n = b0.seed_seq; n <= b1.last_seq; n++) {
        snprintf(r, sizeof r, "%s/r%llu", tmp, (unsigned long long)n);
        imdb_restore_opts o = {.until_seq = n};
        OK(imdb_restore_ex(r, key, chain, 2, &o, &ri, E));
        const imdb_commit_info *ci = imdb_ci_at(src, n, E);
        imdb_db *c = open_db(r);
        CHECK(c && ci && c->seq == n && ri.last_seq == n && !memcmp(c->head, ci->hash, 32) && !memcmp(ri.last_hash, ci->hash, 32));
        if (c) imdb_close(c);
    }
    /* by time: commit k's own time restores through k, a microsecond less through k - 1 */
    uint64_t k = b1.last_seq - 2;
    const imdb_commit_info *ck = imdb_ci_at(src, k, E);
    CHECK(ck);
    if (ck) {
        uint64_t tk = ck->time_us;
        for (int d = 0; d < 2; d++) {
            snprintf(r, sizeof r, "%s/t%d", tmp, d);
            imdb_restore_opts o = {.until_time = tk - (uint64_t)d};
            OK(imdb_restore_ex(r, key, chain, 2, &o, &ri, E));
            CHECK(ri.last_seq == k - (uint64_t)d);
        }
    }
    /* outside the chain: before the snapshot, past the last, before the first commit's time, both at once */
    imdb_restore_opts bad[4] = {{.until_seq = b0.seed_seq - 1}, {.until_seq = b1.last_seq + 1}, {.until_time = 1},
                                {.until_seq = b1.last_seq, .until_time = 1}};
    for (int i = 0; i < 4; i++) {
        snprintf(r, sizeof r, "%s/bad%d", tmp, i);
        imdb_err_clear(E);
        CHECK(imdb_restore_ex(r, key, chain, 2, &bad[i], &ri, E) == IMDB_ERR_INVALID && access(r, F_OK) != 0);
        char t[680];
        snprintf(t, sizeof t, "%s.tmp", r);
        CHECK(access(t, F_OK) != 0);
    }
    imdb_close(src);
}


/* An incremental whose source is not the previous backup's history: two copies of one database (the same identity)
 * that went on apart. The backup of one, then an incremental of the other after it: the other's next commit does not
 * name the backup's last as the one before it, so the incremental is refused by name and no file is left */
static void t_backup_incremental_history(void)
{
    const char *tmp = test_tmpdir();
    char a[600], b[600], kf[600], fa[600], fb[600];
    snprintf(a, sizeof a, "%s/a", tmp);
    snprintf(b, sizeof b, "%s/b", tmp);
    snprintf(kf, sizeof kf, "%s/backup.key", tmp);
    snprintf(fa, sizeof fa, "%s/a.bak", tmp);
    snprintf(fb, sizeof fb, "%s/b-after-a.bak", tmp);
    uint8_t root_seed[IMDB_SEED_LEN], key[IMDB_BACKUP_KEY_LEN], id[32], head[32];
    test_rand_bytes(root_seed, sizeof root_seed);
    imdb_signer root;
    imdb_signer_init(&root, root_seed);
    uint64_t seq = 0;
    CHECK(make_source(a, root.pk, &seq, head) == 0);
    CHECK(copy_tree(a, b) == 0);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    for (int side = 0; side < 2; side++) { /* a: two more commits; b: four others */
        imdb_db *db = open_db(side ? b : a);
        CHECK(db);
        if (!db) return;
        for (int64_t i = 0; i < (side ? 4 : 2); i++) OK(ins1(db, 5000 + i, side, i, side ? "b's own" : "a's own"));
        imdb_close(db);
    }
    imdb_backup_info ba, bb;
    OK(imdb_backup_full(a, fa, key, &ba, E));
    imdb_err_clear(E);
    CHECK(imdb_backup_incremental(b, fa, fb, key, &bb, E) == IMDB_ERR_STATE && strstr(g_e.msg, "another history"));
    CHECK(access(fb, F_OK) != 0);
    char t[640];
    snprintf(t, sizeof t, "%s.tmp", fb);
    CHECK(access(t, F_OK) != 0);
}


static int64_t sql_i64(imdb_db *db, const char *sql)
{
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    imdb_err_clear(&g_e);
    int64_t v = INT64_MIN;
    if (imdb_exec_one(&s, sql, strlen(sql), NULL, 0, &r, &g_e) == 0) {
        if (r.nrows == 1 && !r.cells[0].null) v = r.cells[0].wide ? (int64_t)r.cells[0].i128 : r.cells[0].v.i;
        imdb_result_free(&r);
    }
    imdb_session_close(&s);
    return v;
}

typedef struct live_ctx {
    volatile uint64_t *seq; /* the writer's last commit, in memory both processes share */
    uint64_t at_hook;
    int calls;
} live_ctx;

static void live_between(void *ctx) /* between the seed and the log: 200 more commits land while the backup runs */
{
    live_ctx *c = ctx;
    c->calls++;
    c->at_hook = __atomic_load_n(c->seq, __ATOMIC_ACQUIRE);
    for (int spin = 0; spin < 60000 && __atomic_load_n(c->seq, __ATOMIC_ACQUIRE) < c->at_hook + 200; spin++) {
        struct timespec ts = {0, 1000000L};
        nanosleep(&ts, NULL);
    }
}

/* A backup of a database another process writes to throughout (the database operating, P0): the writer commits a row
 * a commit and publishes every 400, from before the backup starts until after it ends; the hook between the backup's
 * parts waits for 200 more of its commits, so the log part reads a log that grew after the seed was taken and goes
 * on growing under it. The copy is the source at the backup's last commit: that commit the source's own at that
 * sequence, its rows the source's AS OF it, VERIFY passing; the 200 are in it, and what came after the backup is not */
static void t_backup_live_writer(void)
{
    const char *tmp = test_tmpdir();
    char p[600], out[600], r[600], kf[600];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(out, sizeof out, "%s/live.bak", tmp);
    snprintf(r, sizeof r, "%s/restored", tmp);
    snprintf(kf, sizeof kf, "%s/backup.key", tmp);
    uint8_t root_seed[IMDB_SEED_LEN], key[IMDB_BACKUP_KEY_LEN], id[32], head[32];
    test_rand_bytes(root_seed, sizeof root_seed);
    imdb_signer root;
    imdb_signer_init(&root, root_seed);
    uint64_t seq = 0;
    CHECK(make_source(p, root.pk, &seq, head) == 0);
    OK(imdb_backup_key_create(kf, id, E));
    OK(imdb_backup_key_load(kf, key, E));
    void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(map != MAP_FAILED);
    if (map == MAP_FAILED) return;
    volatile uint64_t *shared = map;
    *shared = 0;
    int ready[2], stop[2];
    CHECK(pipe(ready) == 0 && pipe(stop) == 0);
    CHECK(fcntl(stop[0], F_SETFL, O_NONBLOCK) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) { /* the writer: commits until told to stop, then 50 more the backup must not hold */
        imdb_db *w = open_db(p);
        if (!w) _exit(2);
        char c = 1;
        int64_t i = 100000, after = -1;
        for (;; i++) {
            if (ins1(w, i, 3, i, "live")) _exit(4);
            if (i % 400 == 0 && imdb_checkpoint(w, E)) _exit(5);
            __atomic_store_n(shared, w->seq, __ATOMIC_RELEASE);
            if (i == 100020 && write(ready[1], &c, 1) != 1) _exit(3); /* 20 commits in: the backup may start */
            if (after < 0 && read(stop[0], &c, 1) == 1) after = i;
            if (after >= 0 && i >= after + 50) break;
            if (i > 2000000) _exit(6); /* never told: the parent is gone */
        }
        imdb_close(w);
        _exit(0);
    }
    char c = 0;
    CHECK(read(ready[0], &c, 1) == 1);
    uint64_t at_start = __atomic_load_n(shared, __ATOMIC_ACQUIRE);
    live_ctx lc = {.seq = shared};
    imdb_backup_test_between(live_between, &lc);
    imdb_backup_info bi;
    int rc = imdb_backup_full(p, out, key, &bi, E);
    imdb_backup_test_between(NULL, NULL);
    uint64_t at_end = __atomic_load_n(shared, __ATOMIC_ACQUIRE);
    CHECK(write(stop[1], &c, 1) == 1);
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(ready[0]);
    close(ready[1]);
    close(stop[0]);
    close(stop[1]);
    munmap(map, 4096);
    OK_RC(rc);
    /* the seed taken at or after the start, the hook once, the 200 in the backup, nothing past the backup's end */
    CHECK(lc.calls >= 1 && lc.at_hook >= at_start && bi.last_seq >= lc.at_hook + 200 && bi.last_seq <= at_end);
    imdb_db *src = open_db(p);
    CHECK(src);
    if (!src) return;
    CHECK(src->seq >= bi.last_seq + 50);
    const imdb_commit_info *ci = imdb_ci_at(src, bi.last_seq, E);
    CHECK(ci && memcmp(ci->hash, bi.last_hash, 32) == 0); /* the source's own commit at that sequence */
    char q[160];
    snprintf(q, sizeof q, "SELECT COUNT(*) FROM txns AS OF %llu", (unsigned long long)bi.last_seq);
    int64_t n_src = sql_i64(src, q);
    snprintf(q, sizeof q, "SELECT SUM(amount) FROM txns AS OF %llu", (unsigned long long)bi.last_seq);
    int64_t sum_src = sql_i64(src, q);
    imdb_close(src);
    const char *files[1] = {out};
    imdb_backup_info ri;
    OK(imdb_restore(r, key, files, 1, &ri, E));
    imdb_db *db = open_db(r);
    CHECK(db);
    if (!db) return;
    CHECK(db->seq == bi.last_seq && memcmp(db->head, bi.last_hash, 32) == 0);
    CHECK(n_src >= 200 && sql_i64(db, "SELECT COUNT(*) FROM txns") == n_src);
    CHECK(sql_i64(db, "SELECT SUM(amount) FROM txns") == sum_src);
    imdb_verify_report vr;
    OK(imdb_verify(db, &vr, E));
    imdb_close(db);
}

const test_case backup_tests[] = {
    {"backup_xchacha_openssl", t_backup_xchacha_openssl},
    {"backup_key_file", t_backup_key_file},
    {"backup_roundtrip", t_backup_roundtrip},
    {"backup_whole_log", t_backup_whole_log},
    {"backup_at_snapshot", t_backup_at_snapshot},
    {"backup_empty", t_backup_empty},
    {"backup_damage", t_backup_damage},
    {"backup_chunks_moved", t_backup_chunks_moved},
    {"backup_verify", t_backup_verify},
    {"backup_incremental", t_backup_incremental},
    {"backup_point_in_time", t_backup_point_in_time},
    {"backup_incremental_history", t_backup_incremental_history},
    {"backup_live_writer", t_backup_live_writer},
};
const size_t backup_ntests = sizeof backup_tests / sizeof backup_tests[0];
