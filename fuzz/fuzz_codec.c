/* UTF-8 validation (differential against an independent decoder), row and
 * schema decoding, and the literal parsers. */
#include "../src/codec.h"
#include "fuzz_common.h"

static bool ref_utf8(const uint8_t *s, size_t n)
{
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        uint32_t cp;
        size_t len;
        if (c < 0x80) cp = c, len = 1;
        else if ((c & 0xE0) == 0xC0) cp = c & 0x1F, len = 2;
        else if ((c & 0xF0) == 0xE0) cp = c & 0x0F, len = 3;
        else if ((c & 0xF8) == 0xF0) cp = c & 0x07, len = 4;
        else return false;
        if (len > n - i) return false;
        for (size_t k = 1; k < len; k++) {
            if ((s[i + k] & 0xC0) != 0x80) return false;
            cp = cp << 6 | (s[i + k] & 0x3F);
        }
        static const uint32_t minv[5] = {0, 0, 0x80, 0x800, 0x10000};
        if (cp == 0 || cp < minv[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *b = malloc(size ? size : 1);
    memcpy(b, data, size);
    size_t bad;
    if (imdb_utf8_valid(b, size, &bad) != ref_utf8(b, size)) abort(); /* differential */
    imdb_err e = {0};
    for (int w = 0; w < FUZZ_NSCHEMAS; w++) {
        imdb_schema s;
        fuzz_schema(w, &s);
        imdb_value vals[IMDB_MAX_COLS];
        imdb_err_clear(&e);
        if (imdb_row_decode(&s, b, size, vals, &e) == 0) {
            imdb_buf out;
            imdb_buf_init(&out);
            imdb_err_clear(&e);
            if (imdb_row_encode(&s, vals, &out, &e) != 0 || out.len != size || memcmp(out.p, b, size) != 0)
                abort(); /* decode -> encode must round-trip exactly (canonical form) */
            imdb_buf_free(&out);
        }
    }
    imdb_rd r;
    imdb_rd_init(&r, b, size);
    imdb_schema s;
    imdb_err_clear(&e);
    (void)imdb_schema_decode(&r, &s, &e);
    int64_t v;
    imdb_err_clear(&e);
    (void)imdb_parse_int64((const char *)b, size, &v, &e);
    imdb_err_clear(&e);
    (void)imdb_parse_decimal((const char *)b, size, 18, size ? b[0] % 19 : 2, &v, &e);
    imdb_err_clear(&e);
    if (imdb_parse_float64((const char *)b, size, &v, &e) == 0) {
        /* a valid key, and the shortest round-trip form reads back to the same key */
        if (!imdb_f64_key_valid(v)) abort();
        imdb_buf out;
        imdb_buf_init(&out);
        imdb_format_float64(v, &out);
        int64_t v2;
        imdb_err e2 = {0};
        if (imdb_parse_float64((const char *)out.p, out.len, &v2, &e2) != 0 || v2 != v) abort();
        imdb_buf_free(&out);
    }
    imdb_err_clear(&e);
    if (imdb_parse_timestamp((const char *)b, size, &v, &e) == 0) {
        imdb_buf out;
        imdb_buf_init(&out);
        imdb_format_timestamp(v, &out);
        int64_t v2;
        imdb_err e2 = {0};
        if (imdb_parse_timestamp((const char *)out.p, out.len, &v2, &e2) != 0 || v2 != v) abort();
        imdb_buf_free(&out);
    }
    free(b);
    return 0;
}
