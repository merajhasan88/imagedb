/* L (N2's records): roles and grants (docs/roles-design.md). SCRAM: PBKDF2 and HMAC against OpenSSL at the edges,
 * RFC 7677's exchange from the verifier the engine makes, PostgreSQL's verifier text both ways and every malformed form
 * refused with no message holding it. The statements and every refusal by name; one encoding of a GRANT and of an
 * ALTER (none that changes nothing commits); the drops' ends; the differential: seeded statements, the catalog's bytes
 * (manifest 18's sections 5 and 6) alike from the live handle, a full replay and a snapshot open with its tail, VERIFY
 * on each. */
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "../../src/backup.h"
#include "../../src/db_internal.h"
#include "../../src/log.h"
#include "../../src/logdir.h"
#include "../../src/role.h"
#include "../../src/scram.h"
#include "../../src/sha256.h"
#include "../../src/sql.h"
#include "../../src/sql_internal.h"
#include "thelp.h"

static imdb_session g_s;
static char g_out[1 << 16];

static const char *render(const imdb_result *r)
{
    imdb_buf b;
    imdb_buf_init(&b);
    if (r->has_rows) imdb_result_render(r, true, &b);
    else imdb_buf_put_str(&b, r->status);
    if (imdb_buf_check(&b, &g_e)) snprintf(g_out, sizeof g_out, "ERR render");
    else snprintf(g_out, sizeof g_out, "%.*s", (int)b.len, (const char *)b.p);
    imdb_buf_free(&b);
    return g_out;
}

static const char *csv(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    if (imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e)) {
        snprintf(g_out, sizeof g_out, "ERR %s", g_e.msg);
        return g_out;
    }
    render(&r);
    imdb_result_free(&r);
    return g_out;
}

static int run(const char *sql)
{
    imdb_result r;
    imdb_err_clear(&g_e);
    int rc = imdb_exec_one(&g_s, sql, strlen(sql), NULL, 0, &r, &g_e);
    if (!rc) imdb_result_free(&r);
    return rc;
}

#define EXPECT(sql, want)                                                                                          \
    do {                                                                                                           \
        const char *got_ = csv(sql);                                                                               \
        bool ok_ = !strncmp((want), "ERR ", 4) ? !strncmp(got_, "ERR ", 4) && strstr(got_ + 4, (want) + 4) != NULL \
                                               : !strcmp(got_, (want));                                            \
        if (!ok_) {                                                                                                \
            char m_[3000];                                                                                         \
            snprintf(m_, sizeof m_, "%.900s\n      want: %.900s\n      got:  %.900s", (sql), (want), got_);        \
            test_fail(__FILE__, __LINE__, m_);                                                                     \
        }                                                                                                          \
    } while (0)

static imdb_db *open_with(const char *dir, bool full_replay)
{
    imdb_open_opts o = {.sync = 0, .full_replay = full_replay};
    imdb_db *db = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &db, &e)) {
        fprintf(stderr, "    open%s: %s\n", full_replay ? " (a full replay)" : "", e.msg);
        return NULL;
    }
    imdb_session_init(&g_s, db);
    return db;
}

static void done(imdb_db *db)
{
    imdb_session_close(&g_s);
    imdb_close(db);
}

static int verify_db(imdb_db *db)
{
    imdb_verify_report vr;
    memset(&vr, 0, sizeof vr);
    imdb_err_clear(&g_e);
    int rc = imdb_verify(db, &vr, &g_e);
    if (rc) fprintf(stderr, "    verify: %s\n", g_e.msg);
    return rc;
}

static int audit_dir(const char *dir)
{
    const char *bin = getenv("IMDB_AUDIT_BIN");
    if (!bin || !*bin) return 0;
    char cmd[1600];
    snprintf(cmd, sizeof cmd, "'%s' verify '%s' > '%s.audit' 2>&1", bin, dir, dir);
    if (system(cmd) == 0) return 0;
    snprintf(cmd, sizeof cmd, "tail -2 '%s.audit' >&2", dir);
    if (system(cmd)) return 1;
    return 1;
}

/* the catalog as manifest 18's sections 5 and 6 and its roles object encode it */
static void rcat_bytes(imdb_db *db, imdb_buf *b) /* sections 5 and 6, and the roles object */
{
    imdb_buf o;
    uint8_t h[32];
    imdb_buf_init(b);
    imdb_buf_init(&o);
    if (imdb_rcat_object(&db->rc, &o, h, &g_e)) return;
    imdb_rcat_put_roles(b, &db->rc, h);
    imdb_rcat_put_grants(b, &db->rc);
    if (o.len) imdb_buf_put(b, o.p, o.len);
    imdb_buf_free(&o);
}

static bool holds(const char *dir, const void *needle, size_t nn); /* stage 2's helpers, below */
static bool keys_of(imdb_db *db, const char *name, uint8_t out[64]);
static bool keys_held(const char *dir, const uint8_t k[64]);
static bool apply_into(const char *rdir, const char *primary, const char *sf, imdb_buf *bytes, uint64_t *pending);
static bool same_bytes(const imdb_buf *a, const imdb_buf *b);

static bool b64_is(const uint8_t *p, size_t n, const char *want)
{
    unsigned char t[128];
    int k = EVP_EncodeBlock(t, p, (int)n);
    return k > 0 && (size_t)k == strlen(want) && !memcmp(t, want, (size_t)k);
}

/* ---- SCRAM ------------------------------------------------------------------------------------------------------- */

static void t_role_scram(void)
{
    /* PBKDF2 against OpenSSL: iterations 1, 2 and 4096, passwords across HMAC's block (keys past 64 bytes hashed), salts
     * of every length to 80 */
    uint8_t pw[200], salt[80];
    test_rand_bytes(pw, sizeof pw);
    test_rand_bytes(salt, sizeof salt);
    static const uint32_t iters[] = {1, 2, 4096};
    static const size_t pls[] = {0, 1, 63, 64, 65, 200};
    for (size_t a = 0; a < sizeof iters / sizeof *iters; a++)
        for (size_t b = 0; b < sizeof pls / sizeof *pls; b++)
            for (size_t sl = 0; sl <= 80; sl += a == 2 ? 40 : 1) {
                uint8_t x[32], y[32];
                imdb_pbkdf2_sha256(pw, pls[b], salt, sl, iters[a], x);
                CHECK(PKCS5_PBKDF2_HMAC((const char *)pw, (int)pls[b], salt, (int)sl, (int)iters[a], EVP_sha256(), 32, y) == 1);
                CHECK(!memcmp(x, y, 32));
            }
    /* RFC 7677's exchange (user "user", password "pencil", its salt, 4096): from the verifier the engine makes, the
     * server's signature and the client's proof the RFC prints */
    static const uint8_t rfc_salt[16] = {0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e, 0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa, 0x81};
    imdb_scram v;
    CHECK(imdb_scram_make("pencil", 6, 4096, rfc_salt, 16, &v, &g_e) == 0);
    CHECK(b64_is(v.stored, 32, "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=") && b64_is(v.server, 32, "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="));
    const char *am = "n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,"
                     "i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    uint8_t ssig[32], csig[32], proof[32], ck[32];
    imdb_hmac_sha256(v.server, 32, am, strlen(am), ssig);
    CHECK(b64_is(ssig, 32, "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
    unsigned char praw[64];
    CHECK(EVP_DecodeBlock(praw, (const unsigned char *)"dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", 44) == 33);
    memcpy(proof, praw, 32);
    imdb_hmac_sha256(v.stored, 32, am, strlen(am), csig);
    for (int i = 0; i < 32; i++) ck[i] = proof[i] ^ csig[i];
    uint8_t h[32];
    imdb_sha256(ck, 32, h);
    CHECK(!memcmp(h, v.stored, 32)); /* the proof checks against StoredKey, as a server checks it */
    /* the text both ways; the payload entry's bytes both ways */
    char t[IMDB_SCRAM_TEXT_MAX];
    size_t tl = imdb_scram_format(&v, t, sizeof t);
    CHECK(tl && !strcmp(t, "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:"
                           "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="));
    imdb_scram w;
    CHECK(imdb_scram_parse(t, tl, &w, &g_e) == 0 && !memcmp(&v, &w, sizeof v));
    uint8_t vb[IMDB_SCRAM_BYTES_MAX];
    size_t vl = imdb_scram_encode(&v, vb);
    CHECK(vl == 5 + 16 + 64 && imdb_scram_decode(vb, vl, &w, &g_e) == 0 && !memcmp(&v, &w, sizeof v));
    CHECK(imdb_scram_decode(vb, vl - 1, &w, &g_e) != 0 && imdb_scram_decode(vb, vl + 1, &w, &g_e) != 0);
    /* the longest text: a 64-byte salt, seven digits */
    imdb_scram big;
    memset(salt, 0x41, sizeof salt);
    CHECK(imdb_scram_make("x", 1, 1000000, salt, 64, &big, &g_e) == 0);
    tl = imdb_scram_format(&big, t, sizeof t);
    CHECK(tl == 200 && imdb_scram_parse(t, tl, &w, &g_e) == 0 && !memcmp(&big, &w, sizeof big));
    /* every malformed form refused, and no message holds the text */
    static const char *const bad[] = {
        "SCRAM-SHA-256$999:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$1000001:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$04096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$+4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ=$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gR==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$4096:W22ZaJ0SNQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=", /* a 7-byte salt */
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4g==:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=x",
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=",
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ== $WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$4096:$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=$",
        "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==:WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=",
        "SCRAM-SHA-256$",
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        imdb_err_clear(&g_e);
        CHECK(imdb_scram_parse(bad[i], strlen(bad[i]), &w, &g_e) != 0 && !strstr(g_e.msg, "W22Z") && !strstr(g_e.msg, "$4096"));
    }
    const char *eight = "SCRAM-SHA-256$4096:W22ZaJ0SNY4=$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:"
                        "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=";
    CHECK(imdb_scram_parse(eight, strlen(eight), &w, &g_e) == 0 && w.salt_len == 8); /* the shortest salt taken */
    /* passwords: printable ASCII, 1 to 1,024 bytes, never PostgreSQL's MD5 text */
    imdb_err_clear(&g_e);
    CHECK(imdb_scram_make("", 0, 4096, NULL, 16, &w, &g_e) == IMDB_ERR_INVALID);
    imdb_err_clear(&g_e);
    CHECK(imdb_scram_make("caf\xc3\xa9", 5, 4096, NULL, 16, &w, &g_e) == IMDB_ERR_INVALID && strstr(g_e.msg, "printable ASCII"));
    imdb_err_clear(&g_e);
    CHECK(imdb_scram_make("md5d41d8cd98f00b204e9800998ecf8427e", 35, 4096, NULL, 16, &w, &g_e) == IMDB_ERR_INVALID &&
          strstr(g_e.msg, "MD5") && !strstr(g_e.msg, "d41d8"));
    CHECK(imdb_scram_looks_md5("md5d41d8cd98f00b204e9800998ecf8427e", 35) && !imdb_scram_looks_md5("md5D41D8CD98F00B204E9800998ECF8427E", 35) &&
          !imdb_scram_looks_md5("md5d41d8cd98f00b204e9800998ecf8427", 34));
    imdb_err_clear(&g_e);
    CHECK(imdb_scram_make("x", 1, 999, NULL, 16, &w, &g_e) == IMDB_ERR_INVALID);
    imdb_err_clear(&g_e);
    CHECK(imdb_scram_make("x", 1, 4096, NULL, 7, &w, &g_e) == IMDB_ERR_INVALID);
    imdb_scram s1, s2; /* each verifier its own salt */
    CHECK(imdb_scram_make("same", 4, 4096, NULL, 16, &s1, &g_e) == 0 && imdb_scram_make("same", 4, 4096, NULL, 16, &s2, &g_e) == 0);
    CHECK(memcmp(s1.salt, s2.salt, 16) && memcmp(s1.stored, s2.stored, 32));
}

/* ---- the statements ---------------------------------------------------------------------------------------------- */

static void t_role_sql(void)
{
    const char *dir = test_tmpdir();
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_with(dir, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, v TEXT)"));
    OK(run("CREATE TABLE u (id INT64 PRIMARY KEY)"));
    OK(run("CREATE VIEW vt AS SELECT id FROM t"));
    EXPECT("CREATE ROLE alice LOGIN PASSWORD 'pencil'", "CREATE ROLE alice");
    EXPECT("CREATE USER bob", "CREATE ROLE bob");
    EXPECT("CREATE USER carol NOLOGIN SUPERUSER PASSWORD NULL", "CREATE ROLE carol");
    EXPECT("CREATE ROLE staff", "CREATE ROLE staff");
    EXPECT("CREATE ROLE Alice", "ERR role alice exists already");
    EXPECT("CREATE ROLE public", "ERR a reserved name");
    EXPECT("CREATE ROLE pg_monitor", "ERR a reserved name");
    EXPECT("CREATE ROLE d LOGIN NOLOGIN", "ERR conflicting or redundant options");
    EXPECT("CREATE ROLE d PASSWORD 'a' PASSWORD 'b'", "ERR PASSWORD twice");
    EXPECT("CREATE ROLE d CREATEDB", "ERR role option createdb is not in imagedb yet");
    EXPECT("CREATE ROLE d VALID UNTIL 'infinity'", "ERR role option valid is not in imagedb yet");
    EXPECT("CREATE ROLE d IN ROLE staff", "ERR role option in is not in imagedb yet");
    EXPECT("CREATE ROLE d UNENCRYPTED PASSWORD 'a'", "ERR UNENCRYPTED");
    EXPECT("CREATE ROLE d PASSWORD 'md5d41d8cd98f00b204e9800998ecf8427e'", "ERR an MD5 verifier is not taken");
    EXPECT("CREATE ROLE d PASSWORD ''", "ERR an empty password");
    EXPECT("CREATE ROLE d PASSWORD 'SCRAM-SHA-256$4096:notbase64$x:y'", "ERR SCRAM-SHA-256$<iterations>");
    CHECK(!strstr(csv("CREATE ROLE d PASSWORD 'SCRAM-SHA-256$4096:notbase64$x:y'"), "notbase64")); /* never the text */
    EXPECT("CREATE ROLE d PASSWORD secret", "ERR syntax error at offset");
    CHECK(!strstr(csv("CREATE ROLE d PASSWORD secret"), "secret"));
    EXPECT("PREPARE p AS CREATE ROLE d PASSWORD 'x'", "ERR PREPARE takes a query, INSERT, UPDATE or DELETE");
    { /* a slow statement's line in the event log is its shape: a role statement's its leading keywords alone */
        char sh[256];
        static const char q1[] = "CREATE ROLE d PASSWORD 'hunter2'", q2[] = "ALTER USER d WITH ENCRYPTED PASSWORD 'SCRAM-SHA-256$x'";
        imdb_sql_shape(q1, sizeof q1 - 1, sh, sizeof sh);
        CHECK(!strcmp(sh, "CREATE ROLE ...") && !strstr(sh, "hunter2")); /* L §11: no role name either */
        imdb_sql_shape(q2, sizeof q2 - 1, sh, sizeof sh);
        CHECK(!strcmp(sh, "ALTER USER ..."));
        static const char q3[] = "SHOW GRANTS FOR alice";
        imdb_sql_shape(q3, sizeof q3 - 1, sh, sizeof sh);
        CHECK(!strcmp(sh, "SHOW GRANTS ...")); /* the advisor 21:3x: no role name in a shape */
    }
    EXPECT("CREATE ROLE d PASSWORD 'SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:"
           "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU='", "CREATE ROLE d");
    const imdb_role *rd = imdb_role_by_name(db, "d");
    CHECK(rd && rd->has_ver && rd->vent.len == 5 + 16 + 64);
    if (rd && rd->vent.bytes) { /* the verifier as given, byte for byte */
        imdb_scram v;
        CHECK(imdb_scram_decode(rd->vent.bytes, rd->vent.len, &v, &g_e) == 0 && v.iter == 4096 &&
              b64_is(v.stored, 32, "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY="));
    }
    OK(run("BEGIN"));
    EXPECT("CREATE ROLE e", "ERR CREATE ROLE commits on its own");
    EXPECT("GRANT SELECT ON t TO alice", "ERR GRANT commits on its own");
    OK(run("ROLLBACK"));
    EXPECT("SHOW ROLES", "role,login,superuser,password,created_at\n\"alice\",true,false,true,4\n\"bob\",true,false,false,5\n"
                         "\"carol\",false,true,false,6\n\"staff\",false,false,false,7\n\"d\",false,false,true,8\n");
    /* ALTER: attributes, a rename, a password, PASSWORD NULL; one that changes nothing commits nothing */
    uint64_t s0 = db->seq;
    EXPECT("ALTER ROLE bob LOGIN", "ALTER ROLE bob");
    EXPECT("ALTER ROLE carol PASSWORD NULL", "ALTER ROLE carol");
    CHECK(db->seq == s0);
    EXPECT("ALTER ROLE bob NOLOGIN PASSWORD 'x1'", "ALTER ROLE bob");
    CHECK(db->seq == s0 + 1);
    EXPECT("ALTER ROLE bob RENAME TO robert", "ALTER ROLE bob");
    EXPECT("ALTER ROLE robert RENAME TO alice", "ERR role alice exists already");
    EXPECT("ALTER ROLE robert RENAME TO robert", "ERR role robert exists already");
    EXPECT("ALTER ROLE robert PASSWORD NULL", "ALTER ROLE robert");
    EXPECT("ALTER ROLE nobody LOGIN", "ERR no role nobody");
    EXPECT("ALTER ROLE robert SET search_path = x", "ERR ALTER ROLE ... SET and RESET");
    EXPECT("ALTER ROLE ALL LOGIN", "ERR ALTER ROLE names one role");
    EXPECT("ALTER ROLE robert", "ERR syntax error at offset");
    const imdb_role *rb = imdb_role_by_name(db, "robert");
    CHECK(rb && !rb->has_ver && rb->attrs == 0 && rb->nhist == 2 && rb->hist[0].at <= rb->hist[1].at); /* a name and a verifier */
    /* GRANT and REVOKE: privileges, ALL, views, memberships; nothing that changes nothing commits */
    EXPECT("GRANT SELECT, INSERT ON t, u TO alice, robert", "GRANT");
    s0 = db->seq;
    EXPECT("GRANT SELECT ON t TO alice", "GRANT");
    CHECK(db->seq == s0);
    EXPECT("GRANT ALL PRIVILEGES ON TABLE vt TO staff", "GRANT");
    EXPECT("GRANT INSERT ON vt TO staff", "ERR view vt takes SELECT alone");
    EXPECT("GRANT staff TO alice, robert", "GRANT");
    EXPECT("GRANT alice TO staff", "ERR role alice is a member of role staff already: the membership would close a cycle");
    EXPECT("GRANT staff TO staff", "ERR a role is never a member of itself");
    EXPECT("GRANT carol TO d", "GRANT");
    EXPECT("GRANT d TO staff", "GRANT"); /* staff in d in carol: then carol into staff closes a cycle */
    EXPECT("GRANT staff TO carol", "ERR the membership would close a cycle");
    EXPECT("GRANT SELECT ON t TO PUBLIC", "ERR PUBLIC is not in imagedb yet");
    EXPECT("GRANT SELECT ON t TO alice WITH GRANT OPTION", "ERR WITH GRANT OPTION and WITH ADMIN OPTION are not in imagedb yet");
    EXPECT("GRANT SELECT (v) ON t TO alice", "ERR column privileges are not in imagedb yet");
    EXPECT("GRANT TRUNCATE ON t TO alice", "ERR privilege truncate is not in imagedb yet");
    EXPECT("GRANT USAGE ON SEQUENCE s TO alice", "ERR privileges ON sequence are not in imagedb yet");
    EXPECT("GRANT SELECT ON ALL TABLES IN SCHEMA public TO alice", "ERR ON ALL TABLES IN SCHEMA");
    EXPECT("GRANT SELECT ON nosuch TO alice", "ERR no table or view nosuch");
    EXPECT("GRANT SELECT ON t TO nobody", "ERR no role nobody");
    EXPECT("GRANT ALL TO alice", "ERR syntax error at offset");
    EXPECT("REVOKE GRANT OPTION FOR SELECT ON t FROM alice", "ERR GRANT OPTION FOR");
    EXPECT("REVOKE SELECT ON t FROM alice CASCADE", "ERR REVOKE ... CASCADE");
    EXPECT("REVOKE INSERT ON t, u FROM robert RESTRICT", "REVOKE");
    s0 = db->seq;
    EXPECT("REVOKE INSERT ON t FROM robert", "REVOKE");
    CHECK(db->seq == s0);
    EXPECT("SHOW GRANTS FOR robert", "role,privilege,kind,object\n\"robert\",\"SELECT\",\"TABLE\",\"t\"\n"
                                     "\"robert\",\"SELECT\",\"TABLE\",\"u\"\n\"robert\",\"MEMBER OF\",\"ROLE\",\"staff\"\n");
    /* DROP ROLE: RESTRICT both ways, IF EXISTS, one name */
    EXPECT("DROP ROLE robert", "ERR role robert holds privileges: REVOKE them first");
    EXPECT("REVOKE SELECT ON t, u FROM robert", "REVOKE");
    EXPECT("DROP ROLE robert", "ERR role robert is a member of a role: REVOKE that first");
    EXPECT("REVOKE staff FROM robert", "REVOKE");
    EXPECT("DROP ROLE staff", "ERR role staff holds privileges");
    EXPECT("REVOKE SELECT ON vt FROM staff", "REVOKE");
    EXPECT("DROP ROLE staff", "ERR role staff is a member of a role");
    EXPECT("DROP ROLE d", "ERR role d is a member of a role");
    EXPECT("DROP USER robert", "DROP ROLE robert");
    EXPECT("DROP ROLE robert", "ERR no role robert");
    EXPECT("DROP ROLE IF EXISTS robert", "DROP ROLE robert");
    EXPECT("DROP ROLE alice, staff", "ERR DROP ROLE takes one role");
    EXPECT("CREATE ROLE robert", "CREATE ROLE robert"); /* the name free again: a new id */
    /* a DROP TABLE's and a DROP VIEW's grants end with them */
    EXPECT("GRANT SELECT ON u TO robert", "GRANT");
    EXPECT("GRANT SELECT ON vt TO robert", "GRANT");
    OK(run("DROP VIEW vt"));
    OK(run("DROP TABLE u"));
    EXPECT("SHOW GRANTS FOR robert", "role,privilege,kind,object\n");
    OK(run("CREATE TABLE u (id INT64 PRIMARY KEY)")); /* a new table of the old name: none of the old grants */
    EXPECT("SHOW GRANTS FOR robert", "role,privilege,kind,object\n");
    OK(run("INSERT INTO t VALUES (1, 'a')"));
    OK(run("CHECKPOINT"));
    EXPECT("ALTER ROLE alice PASSWORD 'next'", "ALTER ROLE alice");
    EXPECT("ALTER ROLE alice RENAME TO alicia", "ALTER ROLE alice");
    CHECK(verify_db(db) == 0);
    imdb_buf a, b, c;
    rcat_bytes(db, &a);
    char shown[4096];
    snprintf(shown, sizeof shown, "%s", csv("SHOW GRANTS"));
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_with(dir, true); /* a full replay */
    CHECK(db);
    if (db) {
        rcat_bytes(db, &b);
        CHECK(a.len == b.len && !memcmp(a.p, b.p, a.len));
        CHECK(!strcmp(csv("SHOW GRANTS"), shown));
        CHECK(verify_db(db) == 0);
        imdb_buf_free(&b);
        done(db);
    }
    db = open_with(dir, false); /* the snapshot and its tail */
    CHECK(db);
    if (db) {
        rcat_bytes(db, &c);
        CHECK(a.len == c.len && !memcmp(a.p, c.p, a.len));
        CHECK(verify_db(db) == 0);
        imdb_buf_free(&c);
        done(db);
    }
    imdb_buf_free(&a);
}

/* ---- the differential: the catalog's bytes from the live handle, a full replay and a snapshot with its tail ---------- */

static void draw_roles(char *out, size_t cap, int n)
{
    size_t at = 0;
    int k = 1 + (int)(test_rand() % (uint64_t)n);
    for (int i = 0; i < k; i++) at += (size_t)snprintf(out + at, cap - at, "%sr%d", i ? ", " : "", (int)(test_rand() % 10));
}

static void draw_privs(char *out, size_t cap)
{
    static const char *const p[] = {"SELECT", "INSERT", "UPDATE", "DELETE"};
    if (test_rand() % 6 == 0) {
        snprintf(out, cap, "ALL");
        return;
    }
    size_t at = 0;
    int k = 1 + (int)(test_rand() % 3);
    for (int i = 0; i < k; i++) at += (size_t)snprintf(out + at, cap - at, "%s%s", i ? ", " : "", p[test_rand() % 4]);
}

static void t_role_differential(void)
{
    const char *tmp = test_tmpdir();
    char dir[700], rd[700], sf[760];
    snprintf(dir, sizeof dir, "%s/p", tmp);
    snprintf(rd, sizeof rd, "%s/r", tmp);
    snprintf(sf, sizeof sf, "%s/stream", tmp);
    OK(imdb_init(dir, false, NULL, E));
    imdb_db *db = open_with(dir, false);
    CHECK(db);
    if (!db) return;
    OK(run("CREATE TABLE t0 (id INT64 PRIMARY KEY)"));
    OK(run("CREATE TABLE t1 (id INT64 PRIMARY KEY)"));
    OK(run("CREATE VIEW v0 AS SELECT id FROM t0"));
    OK(run("INSERT INTO t0 VALUES (1)"));
    static const char *const objs[] = {"t0", "t1", "v0", "t0, t1", "t1, v0"};
    char q[512], r1[64], r2[64], pv[64];
    int ok = 0, erased = 0; /* erased: ERASE ROLEs that committed */
    for (int step = 0; step < 700; step++) {
        int k = (int)(test_rand() % 100), a = (int)(test_rand() % 10), b = (int)(test_rand() % 10);
        if (k < 14) {
            snprintf(q, sizeof q, "CREATE ROLE r%d%s%s%s", a, test_rand() % 2 ? " LOGIN" : "", test_rand() % 4 ? "" : " SUPERUSER",
                     test_rand() % 3 == 0 ? " PASSWORD 'pw'" : "");
        } else if (k < 30) {
            static const char *const opt[] = {" LOGIN", " NOLOGIN", " SUPERUSER", " NOSUPERUSER", " PASSWORD 'np'", " PASSWORD NULL",
                                              " LOGIN PASSWORD 'np2'"};
            snprintf(q, sizeof q, "ALTER ROLE r%d%s", a, opt[test_rand() % 7]);
        } else if (k < 36) {
            snprintf(q, sizeof q, "ALTER ROLE r%d RENAME TO r%d", a, b);
        } else if (k < 44) {
            snprintf(q, sizeof q, "DROP ROLE r%d", a);
        } else if (k < 60) {
            draw_privs(pv, sizeof pv);
            draw_roles(r1, sizeof r1, 3);
            snprintf(q, sizeof q, "GRANT %s ON %s TO %s", pv, objs[test_rand() % 5], r1);
        } else if (k < 72) {
            draw_privs(pv, sizeof pv);
            draw_roles(r1, sizeof r1, 3);
            snprintf(q, sizeof q, "REVOKE %s ON %s FROM %s", pv, objs[test_rand() % 5], r1);
        } else if (k < 84) {
            draw_roles(r1, sizeof r1, 2);
            draw_roles(r2, sizeof r2, 2);
            snprintf(q, sizeof q, "GRANT %s TO %s", r1, r2);
        } else if (k < 92) {
            draw_roles(r1, sizeof r1, 2);
            draw_roles(r2, sizeof r2, 2);
            snprintf(q, sizeof q, "REVOKE %s FROM %s", r1, r2);
        } else if (k < 96) { /* stage 2: a live role's earlier entries, every dropped one of the name whole */
            snprintf(q, sizeof q, "ERASE ROLE r%d", a);
        } else if (k < 98) {
            snprintf(q, sizeof q, "CHECKPOINT");
        } else {
            snprintf(q, sizeof q, test_rand() % 2 ? "DROP TABLE t1" : "CREATE TABLE t1 (id INT64 PRIMARY KEY)");
        }
        uint64_t before = db->seq;
        ok += run(q) == 0;
        erased += !strncmp(q, "ERASE", 5) && db->seq > before;
    }
    CHECK(ok > 200); /* a fair share of the drawn statements did something */
    CHECK(erased >= 4); /* stage 2: ERASE ROLE erased something, again and again */
    if (getenv("IMDB_ROLE_DIFF_SAY")) fprintf(stderr, "    %d of 700 statements did something, %d ERASE ROLEs committed\n", ok, erased);
    CHECK(db->rc.n > 3);
    CHECK(verify_db(db) == 0);
    imdb_buf a, b, c;
    rcat_bytes(db, &a);
    done(db);
    CHECK(audit_dir(dir) == 0);
    db = open_with(dir, true);
    CHECK(db);
    if (db) {
        rcat_bytes(db, &b);
        CHECK(a.len == b.len && !memcmp(a.p, b.p, a.len));
        CHECK(verify_db(db) == 0);
        imdb_buf_free(&b);
        done(db);
    }
    db = open_with(dir, false);
    CHECK(db);
    if (db) {
        rcat_bytes(db, &c);
        CHECK(a.len == c.len && !memcmp(a.p, c.p, a.len));
        CHECK(verify_db(db) == 0);
        imdb_buf_free(&c);
        done(db);
    }
    /* stage 2: a replica fed the redacted log from commit 1: every entry an ERASE named arrives redacted, pending until
     * that ERASE; the CHECKPOINTs between taken unverified; at the end the primary's catalog, no debt left */
    imdb_identity id;
    OK(imdb_identity_read(dir, &id, NULL, &g_e));
    OK(imdb_init_replica(rd, &id, &g_e));
    uint64_t pend = 1;
    imdb_buf x;
    CHECK(apply_into(rd, dir, sf, &x, &pend) && same_bytes(&x, &a) && !pend);
    imdb_buf_free(&x);
    db = open_with(rd, false);
    if (db) {
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(audit_dir(rd) == 0);
    imdb_buf_free(&a);
}


/* ---- the copies (the advisor, 20:3x: the state digest covers no role, so each copy is compared by its catalog's bytes) - */

typedef struct obuf {
    char *p;
    size_t n, cap;
} obuf;

static int obuf_write(void *arg, const char *b, size_t n)
{
    obuf *o = arg;
    if (o->n + n + 1 > o->cap) {
        size_t c = (o->n + n + 1) * 2;
        char *q = realloc(o->p, c);
        if (!q) return -1;
        o->p = q;
        o->cap = c;
    }
    memcpy(o->p + o->n, b, n);
    o->n += n;
    o->p[o->n] = 0;
    return 0;
}

static bool bytes_of(const char *dir, bool full, imdb_buf *b) /* a copy's catalog bytes, opened on its own */
{
    imdb_open_opts o = {.sync = 0, .full_replay = full, .read_only = !full};
    imdb_db *d = NULL;
    imdb_err e = {0};
    if (imdb_open(dir, &o, &d, &e)) {
        fprintf(stderr, "    open %s: %s\n", dir, e.msg);
        return false;
    }
    rcat_bytes(d, b);
    imdb_close(d);
    return true;
}

static bool same_bytes(const imdb_buf *a, const imdb_buf *b) { return a->len == b->len && !memcmp(a->p, b->p, a->len); }

/* a replica fed by ship and apply; a backup restored whole and at a point before an ALTER ROLE; the dump with and
 * without passwords; a stream whose role entry has a byte flipped, refused; a RETIRE whose cut drops the CREATE ROLEs: a
 * replica seeded past it (the current lake's roles object), VERIFY's and the auditor's FLOOR seeds */
static void t_role_copies(void)
{
    const char *dir = test_tmpdir();
    char p[700], r[700], r2[700], sf[760], bad[760], kf[760], bf[760], rs[760], rs2[760], dd[760];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r, sizeof r, "%s/r", dir);
    snprintf(r2, sizeof r2, "%s/r2", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    snprintf(bad, sizeof bad, "%s/stream.bad", dir);
    snprintf(kf, sizeof kf, "%s/bkey", dir);
    snprintf(bf, sizeof bf, "%s/full.bak", dir);
    snprintf(rs, sizeof rs, "%s/restored", dir);
    snprintf(rs2, sizeof rs2, "%s/restored-early", dir);
    snprintf(dd, sizeof dd, "%s/dumped", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_open_opts o = {.sync = 0, .floor_stride = 1};
    imdb_db *db = NULL;
    if (imdb_open(p, &o, &db, &e)) return;
    imdb_session_init(&g_s, db);
    db->no_auto_retire = true;
    imdb_clock_freeze(1772953198ull * 1000000ull);
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY) RETENTION 10 SECONDS"));
    OK(run("CREATE TABLE subj (id INT64 PRIMARY KEY, who INT64 SUBJECT, memo TEXT) RETENTION 10 SECONDS")); /* stage 2's rows */
    OK(run("INSERT INTO subj VALUES (1, 9, 'subject-nine-secret'), (2, 8, 'other')"));
    OK(run("INSERT INTO t VALUES (1), (2)"));
    OK(run("CREATE ROLE alice LOGIN PASSWORD 'pw-one'"));
    uint8_t k1[64]; /* alice's first verifier's keys: erased past the cut below (stage 2) */
    CHECK(keys_of(db, "alice", k1));
    OK(run("CREATE ROLE staff"));
    OK(run("CREATE ROLE gone"));
    OK(run("DROP ROLE gone"));
    OK(run("GRANT SELECT ON t TO staff"));
    OK(run("GRANT staff TO alice"));
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1, early = db->seq;
    imdb_buf b0, b1, x;
    rcat_bytes(db, &b0); /* the catalog at commit early */
    uint8_t kid[32], key[IMDB_BACKUP_KEY_LEN]; /* a full backup at commit early, the incremental at the end */
    OK(imdb_backup_key_create(kf, kid, &g_e));
    OK(imdb_backup_key_load(kf, key, &g_e));
    imdb_backup_info bi;
    OK(imdb_backup_full(p, bf, key, &bi, &g_e));
    OK(run("ALTER ROLE alice PASSWORD 'pw-two'"));
    imdb_buf bm;
    rcat_bytes(db, &bm); /* the catalog at commit early + 1 */
    OK(run("ALTER ROLE staff RENAME TO crew"));
    OK(run("INSERT INTO t VALUES (3)"));
    OK(run("CHECKPOINT"));
    rcat_bytes(db, &b1);
    CHECK(!same_bytes(&b0, &b1));
    CHECK(verify_db(db) == 0);
    /* the dump: no verifier unless asked; with them, a restore holds alice's verifier byte for byte */
    obuf d1 = {0}, d2 = {0};
    OK(imdb_dump_ex(db, 0, 0, obuf_write, &d1, &g_e));
    OK(imdb_dump_ex(db, 0, IMDB_DUMP_ROLE_PASSWORDS, obuf_write, &d2, &g_e));
    CHECK(d1.p && d2.p && !strstr(d1.p, "SCRAM-SHA-256$") && strstr(d1.p, "CREATE ROLE alice LOGIN;") &&
          strstr(d2.p, "CREATE ROLE alice LOGIN PASSWORD 'SCRAM-SHA-256$4096:") && strstr(d2.p, "GRANT crew TO alice;"));
    imdb_scram va, vb;
    const imdb_role *al = imdb_role_by_name(db, "alice");
    CHECK(al && al->has_ver && imdb_scram_decode(al->vent.bytes, al->vent.len, &va, &g_e) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    CHECK(imdb_init(dd, false, NULL, &e) == 0);
    imdb_db *dst = open_with(dd, false);
    CHECK(dst);
    if (dst && d2.p) {
        char *line = d2.p;
        while (line && *line) { /* the roles' lines alone: the dump's tables need its COPY data */
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            if (!strncmp(line, "CREATE ROLE", 11) || (!strncmp(line, "GRANT ", 6) && !strstr(line, " ON "))) OK(run(line));
            line = nl ? nl + 1 : NULL;
        }
        const imdb_role *dal = imdb_role_by_name(dst, "alice");
        CHECK(dal && dal->has_ver && imdb_scram_decode(dal->vent.bytes, dal->vent.len, &vb, &g_e) == 0 &&
              !memcmp(&va, &vb, sizeof va)); /* the verifier as dumped */
        CHECK(dal && imdb_role_member(dal, imdb_role_by_name(dst, "crew")->id));
        done(dst);
    }
    free(d1.p);
    free(d2.p);
    /* a replica fed by ship and apply */
    imdb_identity id;
    OK(imdb_identity_read(p, &id, NULL, &g_e));
    OK(imdb_init_replica(r, &id, &g_e));
    OK(ship_to_file(p, 0, sf, &g_e));
    imdb_open_opts ro = {.sync = 0};
    imdb_db *rep = NULL;
    CHECK(imdb_open(r, &ro, &rep, &e) == 0);
    if (rep) {
        uint64_t applied = 0;
        OK(apply_file(rep, sf, &applied, &g_e));
        rcat_bytes(rep, &x);
        CHECK(same_bytes(&x, &b1));
        imdb_buf_free(&x);
        imdb_close(rep);
    }
    CHECK(audit_dir(r) == 0);
    /* a stream whose CREATE ROLE alice's name entry has a byte flipped: the stream reader refuses it by its commitment */
    size_t sn = 0;
    uint8_t *s = NULL;
    {
        FILE *f = fopen(sf, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long l = ftell(f);
            fseek(f, 0, SEEK_SET);
            s = malloc(l > 0 ? (size_t)l : 1);
            sn = s && l > 0 && fread(s, 1, (size_t)l, f) == (size_t)l ? (size_t)l : 0;
            fclose(f);
        }
    }
    size_t at = 0;
    for (size_t i = 0; i + 9 <= sn && !at; i++) /* u32 5 | "alice": the CREATE's payload entry */
        if (!memcmp(s + i, "\x05\x00\x00\x00" "alice", 9)) at = i + 4;
    CHECK(at);
    if (at) {
        s[at] ^= 1;
        FILE *f = fopen(bad, "wb");
        CHECK(f && fwrite(s, 1, sn, f) == sn);
        if (f) fclose(f);
        char r3[760];
        snprintf(r3, sizeof r3, "%s/r3", dir);
        OK(imdb_init_replica(r3, &id, &g_e));
        imdb_db *rb = NULL;
        CHECK(imdb_open(r3, &ro, &rb, &e) == 0);
        if (rb) {
            uint64_t applied = 0;
            imdb_err_clear(&g_e);
            CHECK(apply_file(rb, bad, &applied, &g_e) != 0 && strstr(g_e.msg, "role's entry does not match its signed commitment"));
            CHECK(rb->rc.n < 1 || !imdb_role_by_name(rb, "alice"));
            imdb_close(rb);
        }
    }
    free(s);
    /* the backups restored: the full alone (commit early), both whole, both to commit early + 1 */
    char bf2[780];
    snprintf(bf2, sizeof bf2, "%s.2", bf);
    OK(imdb_backup_incremental(p, bf, bf2, key, &bi, &g_e));
    const char *one[] = {bf}, *both[] = {bf, bf2};
    OK(imdb_restore(rs, key, one, 1, &bi, &g_e));
    CHECK(bytes_of(rs, false, &x) && same_bytes(&x, &b0));
    imdb_buf_free(&x);
    char rs3[780];
    snprintf(rs3, sizeof rs3, "%s.whole", rs);
    OK(imdb_restore(rs3, key, both, 2, &bi, &g_e));
    CHECK(bytes_of(rs3, false, &x) && same_bytes(&x, &b1));
    imdb_buf_free(&x);
    imdb_restore_opts rop = {.until_seq = early + 1};
    OK(imdb_restore_ex(rs2, key, both, 2, &rop, &bi, &g_e));
    CHECK(bytes_of(rs2, false, &x) && same_bytes(&x, &bm)); /* its snapshot at early, commit early + 1 replayed */
    imdb_buf_free(&x);
    CHECK(audit_dir(rs) == 0 && audit_dir(rs2) == 0 && audit_dir(rs3) == 0);
    /* a RETIRE whose cut drops the CREATE ROLEs: VERIFY's and the auditor's FLOOR seeds take F's roles, their bytes from the
     * current lake's roles object; a replica seeded past the cut holds the primary's catalog */
    db = NULL;
    CHECK(imdb_open(p, &o, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    db->no_auto_retire = true;
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t"));
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    OK(run("ALTER ROLE alice NOLOGIN"));
    /* the advisor 22:4x: pw-two (set at first, above the floor) superseded before the CHECKPOINT r2 is seeded from: an
     * entry r2's log never holds, though past the primary's floor */
    OK(run("ALTER ROLE alice PASSWORD 'pw-three'"));
    OK(run("CHECKPOINT"));
    CHECK(db->log_floor >= first - 1);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    /* a replica seeded past the cut now; then (stage 2) ERASE ROLE of entries all set below the floor: gone's whole (its
     * name in the lake's roles object), alice's first verifier, crew's old name. The redaction's note, VERIFY's and
     * the auditor's floors skip them; the seeded replica takes the ERASEs as its first frames (the advisor 21:3x) */
    OK(imdb_init_replica(r2, &id, &g_e));
    OK(ship_to_file(p, 0, sf, &g_e));
    uint64_t S = 0;
    rep = NULL;
    CHECK(imdb_open(r2, &ro, &rep, &e) == 0);
    if (rep) {
        uint64_t applied = 0;
        OK(apply_file(rep, sf, &applied, &g_e));
        S = rep->seeded;
        CHECK(S && rep->failed); /* a seed: reopen to apply past it */
        imdb_close(rep);
    }
    CHECK(holds(p, "\x04\x00\x00\x00gone", 8) && holds(r2, "\x04\x00\x00\x00gone", 8)); /* the control */
    db = NULL;
    CHECK(imdb_open(p, &o, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    db->no_auto_retire = true;
    OK(run("ERASE ROLE gone"));
    OK(run("ERASE ROLE alice"));
    OK(run("ERASE ROLE crew"));
    done(db);
    /* r5 seeded at the role ERASEs' lake: its first frame an ERASE SUBJECT of rows below its log (the same note: rows' too) */
    char r5[760];
    snprintf(r5, sizeof r5, "%s/r5", dir);
    OK(imdb_init_replica(r5, &id, &g_e));
    OK(ship_to_file(p, 0, sf, &g_e));
    uint64_t S5 = 0;
    rep = NULL;
    CHECK(imdb_open(r5, &ro, &rep, &e) == 0);
    if (rep) {
        uint64_t applied = 0;
        OK(apply_file(rep, sf, &applied, &g_e));
        S5 = rep->seeded;
        CHECK(S5 && rep->failed);
        imdb_close(rep);
    }
    db = NULL;
    CHECK(imdb_open(p, &o, &db, &e) == 0);
    if (!db) return;
    imdb_session_init(&g_s, db);
    db->no_auto_retire = true;
    OK(run("ERASE SUBJECT 9"));
    CHECK(!db->needs_redaction && !db->warning[0]);
    imdb_buf b2;
    rcat_bytes(db, &b2);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
    CHECK(!holds(p, "\x04\x00\x00\x00gone", 8) && !keys_held(p, k1) && !holds(p, "subject-nine-secret", 19));
    rep = NULL;
    CHECK(S && imdb_open(r2, &ro, &rep, &e) == 0);
    /* a seeded copy's floor is its seed's commit, past pw-two's (the primary's is below it): VERIFY's and the auditor's "still in
     * the log" test reads that floor, so pw-two's erasure is complete here (the advisor 22:4x) */
    CHECK(!rep || (rep->log_floor >= first && rep->log_floor >= S));
    if (rep) {
        uint64_t applied = 0;
        OK(ship_to_file(p, S, sf, &g_e));
        OK(apply_file(rep, sf, &applied, &g_e));
        CHECK(!rep->needs_redaction && !rep->warning[0] && !rep->failed);
        if (rep->warning[0]) fprintf(stderr, "    replica: %s\n", rep->warning);
        rcat_bytes(rep, &x);
        CHECK(same_bytes(&x, &b2));
        imdb_buf_free(&x);
        imdb_close(rep);
    }
    CHECK(!holds(r2, "\x04\x00\x00\x00gone", 8) && !keys_held(r2, k1));
    CHECK(bytes_of(r2, false, &x) && same_bytes(&x, &b2));
    imdb_buf_free(&x);
    CHECK(audit_dir(r2) == 0);
    db = open_with(r2, false); /* VERIFY on the seeded replica too (the advisor 22:0x) */
    if (db) {
        CHECK(verify_db(db) == 0);
        done(db);
    }
    rep = NULL;
    CHECK(S5 && imdb_open(r5, &ro, &rep, &e) == 0);
    if (rep) {
        uint64_t applied = 0;
        OK(ship_to_file(p, S5, sf, &g_e));
        OK(apply_file(rep, sf, &applied, &g_e));
        CHECK(!rep->needs_redaction && !rep->warning[0] && !rep->failed);
        rcat_bytes(rep, &x);
        CHECK(same_bytes(&x, &b2));
        imdb_buf_free(&x);
        imdb_close(rep);
    }
    CHECK(!holds(r5, "subject-nine-secret", 19) && !holds(r2, "subject-nine-secret", 19));
    CHECK(audit_dir(r5) == 0);
    db = open_with(r5, false);
    if (db) {
        CHECK(verify_db(db) == 0);
        done(db);
    }
    imdb_buf_free(&b0);
    imdb_buf_free(&b1);
    imdb_buf_free(&b2);
    imdb_buf_free(&bm);
}


/* ---- stage 2: ERASE ROLE (docs/roles-design.md §11) ----------------------------------------------------------------- */

/* a file's bytes raw, or (frames) a log segment's frames untagged (a sector's tag could cut a search: seg_frames) */
static uint8_t *file_bytes(const char *path, const char *name, bool frames, size_t *n)
{
    uint64_t first = 0;
    bool tagged = false;
    if (frames && imdb_logseg_parse(name, &first)) return seg_frames(path, n, &first, &tagged);
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long l = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(l > 0 ? (size_t)l : 1);
    *n = b && l > 0 && fread(b, 1, (size_t)l, f) == (size_t)l ? (size_t)l : 0;
    fclose(f);
    return b;
}

/* whether any file under dir (two levels: log/, objects/, pins/, replicas/ and the top) holds needle */
static bool holds_at(const char *dir, const void *needle, size_t nn, int depth, bool in_log)
{
    DIR *d = opendir(dir);
    if (!d) return false;
    bool hit = false;
    for (struct dirent *de; !hit && (de = readdir(d));) {
        if (de->d_name[0] == '.') continue;
        char path[1200];
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        struct stat st;
        if (lstat(path, &st)) continue;
        if (S_ISDIR(st.st_mode)) {
            if (depth) hit = holds_at(path, needle, nn, depth - 1, !strcmp(de->d_name, "log"));
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;
        size_t n = 0;
        uint8_t *b = file_bytes(path, de->d_name, false, &n); /* raw, and a segment's frames untagged too */
        hit = b && n >= nn && memmem(b, n, needle, nn) != NULL;
        free(b);
        if (!hit && in_log && (b = file_bytes(path, de->d_name, true, &n))) {
            hit = n >= nn && memmem(b, n, needle, nn) != NULL;
            free(b);
        }
    }
    closedir(d);
    return hit;
}

static bool holds(const char *dir, const void *needle, size_t nn) { return holds_at(dir, needle, nn, 2, false); }

/* a role's verifier's StoredKey and ServerKey: what an erasure must leave nowhere */
static bool keys_of(imdb_db *db, const char *name, uint8_t out[64])
{
    const imdb_role *r = imdb_role_by_name(db, name);
    imdb_scram v;
    if (!r || !r->has_ver || imdb_scram_decode(r->vent.bytes, r->vent.len, &v, &g_e)) return false;
    memcpy(out, v.stored, 32);
    memcpy(out + 32, v.server, 32);
    return true;
}

static bool keys_held(const char *dir, const uint8_t k[64]) { return holds(dir, k, 32) || holds(dir, k + 32, 32); }

static void erase_expect(const char *sql, uint32_t entries, uint32_t removed, imdb_db *db)
{
    char want[300];
    snprintf(want, sizeof want, "ERASE ROLE %u names and verifiers (%u dropped roles erased whole) at commit %llu; removed "
             "from log, lake and memory here (SHOW ERASURE: elsewhere)", entries, removed, (unsigned long long)db->seq + 1);
    EXPECT(sql, want);
}

static bool apply_into(const char *rdir, const char *primary, const char *sf, imdb_buf *bytes, uint64_t *pending)
{
    imdb_open_opts ro = {.sync = 0};
    imdb_db *rep = NULL;
    imdb_err e = {0};
    if (imdb_open(rdir, &ro, &rep, &e)) {
        fprintf(stderr, "    open %s: %s\n", rdir, e.msg);
        return false;
    }
    uint64_t applied = 0;
    imdb_err_clear(&g_e);
    bool ok = ship_to_file(primary, rep->seq, sf, &g_e) == 0 && apply_file(rep, sf, &applied, &g_e) == 0;
    if (!ok) fprintf(stderr, "    apply into %s: %s\n", rdir, g_e.msg);
    if (ok && bytes) rcat_bytes(rep, bytes);
    if (pending) *pending = rep->pending_auth + rep->lake_unverified;
    imdb_close(rep);
    return ok;
}

static void t_role_erase(void)
{
    const char *dir = test_tmpdir();
    char p[700], r1[700], r2[700], sf[760], pb[760], hy[760], cmd[4000];
    snprintf(p, sizeof p, "%s/p", dir);
    snprintf(r1, sizeof r1, "%s/r1", dir);
    snprintf(r2, sizeof r2, "%s/r2", dir);
    snprintf(sf, sizeof sf, "%s/stream", dir);
    snprintf(pb, sizeof pb, "%s/p-before", dir);
    snprintf(hy, sizeof hy, "%s/hybrid", dir);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_db *db = open_with(p, false);
    if (!db) return;
    uint8_t ka[64], kc[64], kd1[64], kd2[64], kd3[64];
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY)"));
    OK(run("INSERT INTO t VALUES (1)"));
    OK(run("CREATE ROLE alice LOGIN PASSWORD 'alice-pw-1'"));
    CHECK(keys_of(db, "alice", ka));
    OK(run("CHECKPOINT")); /* the lake's roles object holds alice and her verifier: a CHECKPOINT between them and the ERASE */
    OK(run("ALTER ROLE alice RENAME TO alicia"));
    OK(run("ALTER ROLE alicia PASSWORD 'alice-pw-2'"));
    OK(run("CREATE ROLE carol PASSWORD 'carol-pw'"));
    CHECK(keys_of(db, "carol", kc));
    OK(run("GRANT SELECT ON t TO carol"));
    OK(run("REVOKE SELECT ON t FROM carol"));
    OK(run("DROP ROLE carol"));
    OK(run("CREATE ROLE dave PASSWORD 'dave-pw-1'"));
    CHECK(keys_of(db, "dave", kd1));
    OK(run("DROP ROLE dave"));
    OK(run("CREATE ROLE dave PASSWORD 'dave-pw-2'")); /* the name again: a new role, the dropped one still held */
    CHECK(keys_of(db, "dave", kd2));
    OK(run("ALTER ROLE dave PASSWORD 'dave-pw-3'"));
    CHECK(keys_of(db, "dave", kd3));
    OK(run("CHECKPOINT"));
    done(db);
    /* the controls: before the ERASEs the search finds each name and key; a copy of the directory then (the crash
     * window's lake below), and a replica fed the unredacted log */
    CHECK(holds(p, "alice", 5) && holds(p, "carol", 5) && keys_held(p, ka) && keys_held(p, kc) && keys_held(p, kd1) &&
          keys_held(p, kd2));
    snprintf(cmd, sizeof cmd, "cp -a '%s' '%s'", p, pb);
    CHECK(system(cmd) == 0);
    imdb_identity id;
    OK(imdb_identity_read(p, &id, NULL, &g_e));
    OK(imdb_init_replica(r1, &id, &g_e));
    CHECK(apply_into(r1, p, sf, NULL, NULL));
    db = open_with(p, false);
    if (!db) return;
    uint64_t at = db->seq;
    EXPECT("ERASE ROLE nobody", "ERR no role, live or dropped, holds the name nobody");
    EXPECT("ERASE ROLE public", "ERR no role, live or dropped, holds the name public");
    erase_expect("ERASE ROLE alicia", 2, 0, db); /* alice's name and her first verifier: alicia's earlier entries */
    CHECK(db->seq == at + 1);
    EXPECT("ERASE ROLE alicia", "ERASE ROLE: nothing left to erase (no commit)");
    CHECK(db->seq == at + 1);
    EXPECT("ERASE ROLE alice", "ERR no role, live or dropped, holds the name alice"); /* a renamed role: by its current name */
    OK(run("BEGIN"));
    EXPECT("ERASE ROLE carol", "ERR ERASE runs outside explicit transactions");
    OK(run("ROLLBACK"));
    erase_expect("ERASE ROLE carol", 2, 1, db); /* the dropped carol whole: it leaves the catalog */
    CHECK(!imdb_rcat_by_id(&db->rc, 2));
    erase_expect("ERASE ROLE dave", 3, 1, db); /* the dropped dave whole, and the live dave's earlier verifier */
    EXPECT("SHOW ROLES", "role,login,superuser,password,created_at\n\"alicia\",true,false,true,3\n\"dave\",false,false,true,13\n");
    CHECK(db->rc.last == 4 && db->rc.n == 2);
    EXPECT("CREATE ROLE carol", "CREATE ROLE carol"); /* the name free; a new id (5): the old ones stay spent */
    CHECK(imdb_role_by_name(db, "carol") && imdb_role_by_name(db, "carol")->id == 5);
    OK(run("DROP ROLE carol"));
    erase_expect("ERASE ROLE carol", 1, 1, db);
    {
        const char *se = csv("SHOW ERASURE"); /* the ERASE ROLEs as any erasure: complete in this directory */
        CHECK(strstr(se, "this database") && strstr(se, "complete") && !strstr(se, "pending"));
    }
    imdb_buf b1, x;
    rcat_bytes(db, &b1);
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(!holds(p, "alice", 5) && !holds(p, "carol", 5) && !keys_held(p, ka) && !keys_held(p, kc) && !keys_held(p, kd1) &&
          !keys_held(p, kd2));
    CHECK(holds(p, "alicia", 6) && keys_held(p, kd3)); /* what is kept is found */
    CHECK(audit_dir(p) == 0);
    /* a full replay and a snapshot open: the same catalog */
    CHECK(bytes_of(p, true, &x) && same_bytes(&x, &b1));
    imdb_buf_free(&x);
    CHECK(bytes_of(p, false, &x) && same_bytes(&x, &b1));
    imdb_buf_free(&x);
    /* r1, fed the log before the ERASEs, takes them: it erases what it holds and redacts its own log */
    uint64_t pend = 0;
    CHECK(apply_into(r1, p, sf, &x, &pend) && same_bytes(&x, &b1) && !pend);
    imdb_buf_free(&x);
    CHECK(!holds(r1, "alice", 5) && !holds(r1, "carol", 5) && !keys_held(r1, ka) && !keys_held(r1, kc) && !keys_held(r1, kd1) &&
          !keys_held(r1, kd2) && holds(r1, "alicia", 6));
    CHECK(audit_dir(r1) == 0);
    /* r2, fed the redacted log from commit 1: each redacted entry pending until the ERASE naming it, the CHECKPOINTs
     * between taken unverified, the last ERASE's manifest checking the whole */
    OK(imdb_init_replica(r2, &id, &g_e));
    CHECK(apply_into(r2, p, sf, &x, &pend) && same_bytes(&x, &b1) && !pend);
    imdb_buf_free(&x);
    db = open_with(r2, false);
    if (db) {
        CHECK(verify_db(db) == 0);
        done(db);
    }
    CHECK(!holds(r2, "alice", 5) && !holds(r2, "carol", 5) && !keys_held(r2, ka) && !keys_held(r2, kc) && holds(r2, "alicia", 6));
    CHECK(audit_dir(r2) == 0);
    /* the crash window: the log redacted, the lake still the one before the ERASEs, its roles object holding what they
     * erased: the auditor refuses a lake older than an ERASE (the erasure is not complete there); a writable open finishes
     * the ERASEs' publish (their lake, then GC), and the bytes are gone from it too */
    snprintf(cmd, sizeof cmd, "cp -a '%s' '%s' && rm -rf '%s/log' '%s/DURABLE' && cp -a '%s/log' '%s/DURABLE' '%s/'", pb, hy, hy, hy,
             p, p, hy);
    CHECK(system(cmd) == 0);
    CHECK((!getenv("IMDB_AUDIT_BIN") || audit_dir(hy) != 0) && holds(hy, "carol", 5)); /* refused, where an auditor is given */
    db = open_with(hy, false);
    if (db) done(db);
    CHECK(audit_dir(hy) == 0 && !holds(hy, "alice", 5) && !holds(hy, "carol", 5) && !keys_held(hy, ka) && !keys_held(hy, kc) &&
          !keys_held(hy, kd1) && !keys_held(hy, kd2) && holds(hy, "alicia", 6));
    imdb_buf_free(&b1);
}


/* stage 2: a roles-only ERASE reads no segment (lake.c: no erased set, no pin) and rebuilds no index; at a budget of
 * none, neither the writer's ERASE nor a replica's apply of it loads an image (the advisor 21:3x: nothing pinned it) */
static void t_role_erase_loads(void)
{
    const char *tmp = test_tmpdir();
    char p[700], r[700], sf[760];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(r, sizeof r, "%s/r", tmp);
    snprintf(sf, sizeof sf, "%s/stream", tmp);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_open_opts o = {.sync = 0, .mem_window_us = UINT64_MAX, .seg_cache_bytes = UINT64_MAX};
    imdb_db *db = NULL;
    if (imdb_open(p, &o, &db, &e)) return;
    imdb_session_init(&g_s, db);
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, v INT64)"));
    char q[96];
    for (int g = 0; g < 4; g++) {
        for (int i = 0; i < 50; i++) {
            snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %d)", g * 50 + i, i);
            OK(run(q));
        }
        OK(run("CHECKPOINT"));
    }
    OK(run("CREATE ROLE x PASSWORD 'first'"));
    OK(run("ALTER ROLE x PASSWORD 'second'"));
    OK(run("CHECKPOINT"));
    imdb_table *t = imdb_table_by_name(db, "t");
    CHECK(t && t->nseg >= 4);
    imdb_identity id;
    OK(imdb_identity_read(p, &id, NULL, &g_e));
    OK(imdb_init_replica(r, &id, &g_e));
    imdb_open_opts ro = {.sync = 0, .mem_window_us = UINT64_MAX, .seg_cache_bytes = UINT64_MAX};
    imdb_db *rep = NULL;
    CHECK(imdb_open(r, &ro, &rep, &e) == 0);
    uint64_t applied = 0;
    if (rep) {
        OK(ship_to_file(p, 0, sf, &g_e));
        OK(apply_file(rep, sf, &applied, &g_e));
    }
    /* the replica's baseline: a stream's end recomputes every table (imdb_check_state), reading each segment once at a
     * budget of none; a stream of one role op touching no table costs exactly that */
    OK(run("ALTER ROLE x LOGIN"));
    uint64_t base = 0;
    if (rep) {
        rep->segcache.budget = 0;
        imdb_session s2;
        imdb_session_init(&s2, rep);
        imdb_result rr;
        imdb_err_clear(&g_e);
        if (!imdb_exec_one(&s2, "SELECT COUNT(*) FROM t", 22, NULL, 0, &rr, &g_e)) imdb_result_free(&rr);
        imdb_session_close(&s2);
        uint64_t l0 = rep->segcache.loads;
        OK(ship_to_file(p, rep->seq, sf, &g_e));
        OK(apply_file(rep, sf, &applied, &g_e));
        base = rep->segcache.loads - l0;
        CHECK(applied == 1 && base == t->nseg); /* every segment once, by the check alone */
    }
    db->segcache.budget = 0;
    OK(run("SELECT COUNT(*) FROM t")); /* an operation ends: every image leaves */
    uint64_t loads = db->segcache.loads;
    OK(run("ERASE ROLE x"));
    CHECK(db->segcache.loads == loads && !db->needs_redaction && !db->warning[0]);
    EXPECT("SELECT COUNT(*) FROM t", "count\n200\n");
    CHECK(verify_db(db) == 0);
    done(db);
    if (rep) {
        uint64_t rl = rep->segcache.loads;
        OK(ship_to_file(p, rep->seq, sf, &g_e));
        OK(apply_file(rep, sf, &applied, &g_e));
        if (applied != 1 || rep->segcache.loads != rl + base || rep->needs_redaction || rep->warning[0])
            fprintf(stderr, "    replica: applied %llu, loads %llu -> %llu, redaction %d, warning %s\n", (unsigned long long)applied,
                    (unsigned long long)rl, (unsigned long long)rep->segcache.loads, rep->needs_redaction, rep->warning);
        CHECK(applied == 1 && rep->segcache.loads == rl + base && !rep->needs_redaction && !rep->warning[0]); /* the ERASE none */
        imdb_close(rep);
    }
    CHECK(audit_dir(p) == 0 && audit_dir(r) == 0);
}


/* stage 2: an ERASE ROLE is an erasure as any op 12 is (the backup catalogue's, the restore's debt). b1 (full, before
 * it) holds ann's first verifier; a1 sets a second, a2 a third; ERASE ROLE ann at e1 erases the first two; b2 (the
 * incremental after b1, made after the redaction) carries a1's entry redacted. Restoring b1 with the catalogue is
 * refused; --accept-erased restores it and records the debt (the first verifier there); --reerase applies p's commits
 * through e1 (both gone, p's hash there); the chain whole owes nothing and holds neither; a point in time below e1 is
 * refused with the catalogue, and without it the copy's restore stops on a1's redacted entry, which no ERASE through
 * the point settles (the advisor 21:3x) */
static void t_role_erase_backup(void)
{
    const char *tmp = test_tmpdir();
    char p[700], kf[760], cat[760], b1[760], b2[760], r[760];
    snprintf(p, sizeof p, "%s/p", tmp);
    snprintf(kf, sizeof kf, "%s/bkey", tmp);
    snprintf(cat, sizeof cat, "%s/catalogue", tmp);
    snprintf(b1, sizeof b1, "%s/b1.bak", tmp);
    snprintf(b2, sizeof b2, "%s/b2.bak", tmp);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    uint8_t kid[32], key[IMDB_BACKUP_KEY_LEN], ka[64], kb[64], kc[64];
    OK(imdb_backup_key_create(kf, kid, &g_e));
    OK(imdb_backup_key_load(kf, key, &g_e));
    imdb_db *db = open_with(p, false);
    if (!db) return;
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY)"));
    OK(run("CREATE TABLE s (id INT64 PRIMARY KEY, who INT64 SUBJECT, memo TEXT)")); /* the rows' sibling */
    OK(run("INSERT INTO t VALUES (1)"));
    OK(run("CREATE ROLE ann LOGIN PASSWORD 'ann-pw-1'"));
    CHECK(keys_of(db, "ann", ka));
    done(db);
    imdb_backup_info bi, ri;
    imdb_backup_opts bo = {.catalogue = cat};
    OK(imdb_backup_full_ex(p, b1, key, &bo, &bi, &g_e));
    db = open_with(p, false);
    if (!db) return;
    OK(run("ALTER ROLE ann PASSWORD 'ann-pw-2'"));
    uint64_t a1 = db->seq;
    CHECK(keys_of(db, "ann", kb));
    OK(run("ALTER ROLE ann PASSWORD 'ann-pw-3'"));
    CHECK(keys_of(db, "ann", kc));
    OK(run("ERASE ROLE ann"));
    uint64_t e1 = db->seq;
    OK(run("INSERT INTO s VALUES (1, 5, 'row-five-secret')")); /* w1: a row an ERASE after it erases */
    uint64_t w1 = db->seq;
    OK(run("ERASE SUBJECT 5"));
    OK(run("INSERT INTO t VALUES (2)"));
    done(db);
    OK(imdb_backup_incremental_ex(p, b1, b2, key, &bo, &bi, &g_e));
    const char *one[] = {b1}, *both[] = {b1, b2};
    /* b1 owes e1 */
    snprintf(r, sizeof r, "%s/r1", tmp);
    imdb_restore_opts ro = {.catalogue = cat};
    imdb_err_clear(&g_e);
    CHECK(imdb_restore_ex(r, key, one, 1, &ro, &ri, &g_e) == IMDB_ERR_STATE && strstr(g_e.msg, "before the erasure"));
    ro.accept_erased = true;
    CHECK(imdb_restore_ex(r, key, one, 1, &ro, &ri, &g_e) == 0 && ri.debt_recorded && ri.erasures == 2 && ri.last_erasure == w1 + 1);
    CHECK(keys_held(r, ka)); /* the debt: the first verifier is there */
    snprintf(r, sizeof r, "%s/r2", tmp);
    imdb_restore_opts rr = {.reerase = p};
    CHECK(imdb_restore_ex(r, key, one, 1, &rr, &ri, &g_e) == 0 && ri.reerased && ri.last_seq == w1 + 1 && e1 < w1);
    CHECK(!keys_held(r, ka) && !keys_held(r, kb) && keys_held(r, kc) && !holds(r, "row-five-secret", 15));
    CHECK(audit_dir(r) == 0);
    /* the chain whole: nothing owed, neither erased verifier anywhere */
    snprintf(r, sizeof r, "%s/r3", tmp);
    imdb_restore_opts rc3 = {.catalogue = cat};
    CHECK(imdb_restore_ex(r, key, both, 2, &rc3, &ri, &g_e) == 0 && !ri.erasures && !ri.debt_unknown);
    CHECK(!keys_held(r, ka) && !keys_held(r, kb) && keys_held(r, kc) && !holds(r, "row-five-secret", 15));
    CHECK(audit_dir(r) == 0);
    /* a point in time below e1: with the catalogue, owed and refused; without, a1's entry arrives redacted and no ERASE
     * through the point settles it: refused at the stop (no destination left), and so at w1, whose row the ERASE
     * SUBJECT after it erased (the rows' sibling: before, either restore finished with a copy that refused every query) */
    snprintf(r, sizeof r, "%s/r4", tmp);
    imdb_restore_opts rp = {.catalogue = cat, .until_seq = a1};
    imdb_err_clear(&g_e);
    CHECK(imdb_restore_ex(r, key, both, 2, &rp, &ri, &g_e) == IMDB_ERR_STATE && strstr(g_e.msg, "holding a redacted payload")); /* the stop's refusal first */
    imdb_restore_opts rq = {.until_seq = a1};
    imdb_err_clear(&g_e);
    CHECK(imdb_restore_ex(r, key, both, 2, &rq, &ri, &g_e) == IMDB_ERR_STATE && strstr(g_e.msg, "holding a redacted payload"));
    CHECK(access(r, F_OK) != 0);
    imdb_restore_opts rw = {.until_seq = w1};
    imdb_err_clear(&g_e);
    CHECK(imdb_restore_ex(r, key, both, 2, &rw, &ri, &g_e) == IMDB_ERR_STATE && strstr(g_e.msg, "holding a redacted payload"));
    CHECK(access(r, F_OK) != 0);
    imdb_restore_opts rw2 = {.until_seq = w1 + 1}; /* at the ERASE SUBJECT: settled, and the copy is p's there */
    CHECK(imdb_restore_ex(r, key, both, 2, &rw2, &ri, &g_e) == 0 && ri.last_seq == w1 + 1);
    CHECK(!keys_held(r, ka) && !keys_held(r, kb) && !holds(r, "row-five-secret", 15));
    CHECK(audit_dir(r) == 0);
}


/* stage 2 past a cut: an ERASE ROLE whose entries are all below the floor notes none for the redaction (none is in this
 * log); the redaction then has nothing to read, not every segment (the advisor 22:0x: a skipped note made the crash
 * branch's whole-log scan, v_facts on every row op, loading the images of evicted versions). Rows past the cut, their
 * old versions evicted (eager), a budget of none: the ERASE loads no image */
static void t_role_erase_cut_loads(void)
{
    const char *tmp = test_tmpdir();
    char p[700];
    snprintf(p, sizeof p, "%s/p", tmp);
    imdb_err e = {0};
    CHECK(imdb_init(p, false, NULL, &e) == 0);
    imdb_open_opts o = {.sync = 0, .floor_stride = 1, .seg_cache_bytes = UINT64_MAX};
    imdb_db *db = NULL;
    if (imdb_open(p, &o, &db, &e)) return;
    imdb_session_init(&g_s, db);
    db->no_auto_retire = true;
    imdb_clock_freeze(1772953198ull * 1000000ull);
    OK(run("CREATE TABLE t (id INT64 PRIMARY KEY, v INT64) RETENTION 10 SECONDS"));
    OK(run("CREATE ROLE z PASSWORD 'zz-1'"));
    OK(run("ALTER ROLE z PASSWORD 'zz-2'")); /* its first verifier an earlier entry, set below the cut to come */
    char q[96];
    for (int i = 0; i < 100; i++) {
        snprintf(q, sizeof q, "INSERT INTO t VALUES (%d, %d)", i, i);
        OK(run(q));
    }
    OK(run("CHECKPOINT"));
    uint64_t first = db->seq + 1;
    OK(run("UPDATE t SET v = v + 1"));
    OK(run("CHECKPOINT"));
    imdb_clock_offset(15 * 1000000ll);
    OK(run("SELECT COUNT(*) FROM t"));
    imdb_err_clear(&g_e);
    OK(imdb_retire(db, first - 1, &g_e));
    CHECK(db->log_floor >= first - 1);
    db->evict_eager = true; /* every publish evicts to itself: the versions the updates end leave memory */
    OK(run("UPDATE t SET v = v + 1"));
    OK(run("UPDATE t SET v = v + 1"));
    OK(run("CHECKPOINT"));
    db->segcache.budget = 0;
    OK(run("SELECT COUNT(*) FROM t"));
    uint64_t loads = db->segcache.loads;
    OK(run("ERASE ROLE z"));
    if (db->segcache.loads != loads)
        fprintf(stderr, "    the ERASE loaded %llu images\n", (unsigned long long)(db->segcache.loads - loads));
    CHECK(db->segcache.loads == loads && !db->needs_redaction && !db->warning[0]);
    EXPECT("SELECT COUNT(*) FROM t", "count\n100\n");
    CHECK(verify_db(db) == 0);
    done(db);
    CHECK(audit_dir(p) == 0);
}

const test_case role_tests[] = {
    {"role_scram", t_role_scram},
    {"role_sql", t_role_sql},
    {"role_differential", t_role_differential},
    {"role_copies", t_role_copies},
    {"role_erase", t_role_erase},
    {"role_erase_loads", t_role_erase_loads},
    {"role_erase_backup", t_role_erase_backup},
    {"role_erase_cut_loads", t_role_erase_cut_loads},
};
const size_t role_ntests = sizeof role_tests / sizeof *role_tests;
