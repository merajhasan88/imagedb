/* A row's transient TEXT may be reused only after every new value is encoded. */
#include "../../src/db.h"
#include "../../src/sql.h"
#include "test.h"

static int run(imdb_session *s, const char *q, imdb_result *r, imdb_err *e)
{
    return imdb_exec_one(s, q, strlen(q), NULL, 0, r, e);
}

static void t_text_row_reuse(void)
{
    const char *dir = test_tmpdir();
    imdb_db *db = NULL;
    imdb_err e = {0};
    imdb_open_opts o = {.sync = 0};
    CHECK(!imdb_init(dir, false, NULL, &e));
    CHECK(!imdb_open(dir, &o, &db, &e));
    imdb_session s;
    imdb_session_init(&s, db);
    imdb_result r;
    int rc = run(&s, "CREATE TABLE t(id INT64 PRIMARY KEY, a TEXT NOT NULL, b TEXT)", &r, &e);
    imdb_result_free(&r);
    if (rc) goto done;
    uint8_t a[8192], b[12288];
    memset(a, 'a', sizeof a);
    memset(b, 'b', sizeof b);
    imdb_table *t = imdb_table_by_name(db, "t");
    rc = imdb_begin(db, &e);
    for (int i = 0; !rc && i < 40; i++) {
        imdb_value v[] = {{.type = IMDB_T_INT64, .i = i},
                         {.type = IMDB_T_TEXT, .s = a, .len = 1u + (unsigned)i * 197u},
                         {.type = IMDB_T_TEXT, .s = b, .len = 1u + (unsigned)i * 293u}};
        rc = imdb_insert(db, t, v, &e);
    }
    if (!rc) rc = imdb_commit(db, &e);
    for (int pass = 0; !rc && pass < 2; pass++) {
        if (pass) {
            rc = run(&s, "CHECKPOINT", &r, &e);
            imdb_result_free(&r);
        }
        if (!rc) {
            rc = run(&s, "UPDATE t SET a = b, b = a", &r, &e);
            imdb_result_free(&r);
        }
        if (!rc) rc = run(&s, "SELECT * FROM t ORDER BY id", &r, &e);
        if (!rc) {
            if (r.nrows != 40) test_fail(__FILE__, __LINE__, "all updated rows survive");
            for (uint64_t i = 0; i < r.nrows; i++) {
                const imdb_value *va = &r.cells[i * r.ncols + 1].v, *vb = &r.cells[i * r.ncols + 2].v;
                uint32_t al = 1u + (uint32_t)i * (pass ? 197u : 293u), bl = 1u + (uint32_t)i * (pass ? 293u : 197u);
                if (va->len != al || vb->len != bl || memcmp(va->s, pass ? a : b, al) || memcmp(vb->s, pass ? b : a, bl))
                    test_fail(__FILE__, __LINE__, "TEXT assignment uses both old columns before buffer reuse");
            }
        }
        imdb_result_free(&r);
    }
done:
    if (rc) test_fail(__FILE__, __LINE__, e.msg);
    imdb_session_close(&s);
    imdb_close(db);
}

const test_case reviewmem_tests[] = {{"review1105_text_row_reuse", t_text_row_reuse}};
const size_t reviewmem_ntests = sizeof reviewmem_tests / sizeof *reviewmem_tests;
