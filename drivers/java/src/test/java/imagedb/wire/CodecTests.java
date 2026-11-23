package imagedb.wire;

import static imagedb.test.T.check;
import static imagedb.test.T.eq;
import static imagedb.test.T.run;
import static imagedb.test.T.throwsIt;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * The codec against imagedb's own vectors (tests/unit/t_wire.c: each table copied with its line range) and §4's pinned
 * SCRAM exchanges, byte for byte. No server.
 */
public final class CodecTests {
    private CodecTests() {}

    static byte[] h(String hex) { return Der.unhex(hex); }

    static String hex(byte[] b) { return Der.hex(b); }

    static byte[] u(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    static int code(Exception x) { return x instanceof WireException ? ((WireException) x).code() : -1; }

    /** decode a value from exactly these bytes: the code of a refusal, or 0 */
    static int valueVerdict(byte[] b) {
        try {
            Value.decode(b);
            return 0;
        } catch (WireException x) {
            return x.code();
        }
    }

    static final class Vec {
        final Value v;
        final String hex;

        Vec(Value v, String hex) {
            this.v = v;
            this.hex = hex;
        }
    }

    /** t_wire.c lines 55-84 (kVecs): the contract, each type's bytes */
    static List<Vec> kVecs() throws WireException {
        byte[] uuid = new byte[16];
        for (int i = 0; i < 16; i++) uuid[i] = (byte) i;
        List<Vec> v = new ArrayList<>();
        v.add(new Vec(Value.nullOf(Wire.T_NONE), "80"));
        v.add(new Vec(Value.nullOf(Wire.T_INT64), "81"));
        v.add(new Vec(Value.nullOf(Wire.T_DECIMAL), "85"));
        v.add(new Vec(Value.nullOf(Wire.T_ENUM), "8d"));
        v.add(new Vec(Value.int64(-2), "01 feffffffffffffff"));
        v.add(new Vec(Value.int64(Long.MIN_VALUE), "01 0000000000000080"));
        v.add(new Vec(Value.float64Bits(0x3ff8000000000000L), "02 000000000000f83f")); // 1.5
        v.add(new Vec(Value.float64Bits(0), "02 0000000000000000"));
        v.add(new Vec(Value.bool(true), "03 01"));
        v.add(new Vec(Value.bool(false), "03 00"));
        v.add(new Vec(Value.textUtf8(new byte[] {'h', (byte) 0xc3, (byte) 0xa9}), "04 03000000 68c3a9"));
        v.add(new Vec(Value.textUtf8(new byte[0]), "04 00000000"));
        v.add(new Vec(Value.decimal(BigInteger.valueOf(-12345), 2), "05 02 c7cfffffffffffffffffffffffffffff"));
        v.add(new Vec(Value.decimal(BigInteger.ZERO, 0), "05 00 00000000000000000000000000000000"));
        v.add(new Vec(Value.timestamp(1), "06 0100000000000000"));
        v.add(new Vec(Value.timestamp(-62135596800000000L), "06 0040d400014023ff"));
        v.add(new Vec(Value.timestamptz(-1), "07 ffffffffffffffff"));
        v.add(new Vec(Value.timestamptz(253402300799999999L), "07 ff5f73cc0c448403"));
        v.add(new Vec(Value.date(-719162), "08 c606f5ff"));
        v.add(new Vec(Value.date(2932896), "08 a0c02c00"));
        v.add(new Vec(Value.time(0), "09 0000000000000000"));
        v.add(new Vec(Value.time(86399999999L), "09 ff5fd71d14000000"));
        v.add(new Vec(Value.uuid(uuid), "0a 000102030405060708090a0b0c0d0e0f"));
        v.add(new Vec(Value.bytea(new byte[] {0, (byte) 0xff}), "0b 02000000 00ff"));
        v.add(new Vec(Value.interval(1, -2, 3), "0c 01000000 feffffff 0300000000000000"));
        v.add(new Vec(Value.interval(Integer.MIN_VALUE, Integer.MAX_VALUE, Long.MIN_VALUE), "0c 00000080 ffffff7f 0000000000000080"));
        v.add(new Vec(Value.enumUtf8(new byte[] {'a'}), "0d 01 61"));
        v.add(new Vec(Value.enumUtf8(new byte[0]), "0d 00"));
        return v;
    }

    public static void all() {
        run("codec_value_vectors (t_wire.c 55-104)", () -> {
            for (Vec x : kVecs()) {
                byte[] want = h(x.hex);
                eq(hex(want), hex(x.v.encode()), "encode " + x.hex);
                Value d = Value.decode(want);
                check(d.equals(x.v), "decode " + x.hex);
                for (int cut = 0; cut < want.length; cut++)
                    check(valueVerdict(Arrays.copyOf(want, cut)) != 0, "prefix " + cut + " of " + x.hex + " refused");
                byte[] more = Arrays.copyOf(want, want.length + 1);
                check(valueVerdict(more) != 0, "a byte past " + x.hex + " refused");
            }
            // the Java types the vectors stand for
            eq(java.time.LocalDateTime.of(1, 1, 1, 0, 0), Value.decode(h("06 0040d400014023ff")).localDateTime(), "TIMESTAMP 0001-01-01");
            eq(java.time.Instant.parse("9999-12-31T23:59:59.999999Z"), Value.decode(h("07 ff5f73cc0c448403")).instant(), "TIMESTAMPTZ max");
            eq(java.time.LocalDate.of(1, 1, 1), Value.decode(h("08 c606f5ff")).localDate(), "DATE min");
            eq(java.time.LocalDate.of(9999, 12, 31), Value.decode(h("08 a0c02c00")).localDate(), "DATE max");
            eq(java.time.LocalTime.of(23, 59, 59, 999999000), Value.decode(h("09 ff5fd71d14000000")).localTime(), "TIME max");
            eq(java.util.UUID.fromString("00010203-0405-0607-0809-0a0b0c0d0e0f"), Value.decode(h("0a 000102030405060708090a0b0c0d0e0f")).uuid(), "UUID");
            eq(new java.math.BigDecimal("-123.45"), Value.decode(h("05 02 c7cfffffffffffffffffffffffffffff")).decimal(), "DECIMAL -123.45");
            eq(1.5, Value.decode(h("02 000000000000f83f")).float64(), "FLOAT64 1.5");
            eq("hé", Value.decode(h("04 03000000 68c3a9")).string(), "TEXT hé");
            eq(new Interval(1, -2, 3), Value.decode(h("0c 01000000 feffffff 0300000000000000")).toJava(), "INTERVAL");
            // the java.time factories give the vectors' bytes
            eq("0640d400014023ff".replace("0640", "06 0040").replace(" ", ""), hex(Value.timestamp(java.time.LocalDateTime.of(1, 1, 1, 0, 0)).encode()), "LocalDateTime -> TIMESTAMP");
            eq("07ff5f73cc0c448403", hex(Value.timestamptz(java.time.Instant.parse("9999-12-31T23:59:59.999999Z")).encode()), "Instant -> TIMESTAMPTZ");
            eq("0a000102030405060708090a0b0c0d0e0f", hex(Value.uuid(java.util.UUID.fromString("00010203-0405-0607-0809-0a0b0c0d0e0f")).encode()), "UUID object");
            eq("0502c7cfffffffffffffffffffffffffffff", hex(Value.decimal(new java.math.BigDecimal("-123.45")).encode()), "BigDecimal");
        });

        run("codec_vectors_in_t_wire (the copied vectors still in tests/unit/t_wire.c, byte for byte)", () -> {
            String path = System.getProperty("imdb.twire");
            java.nio.file.Path f = path == null ? null : java.nio.file.Paths.get(path);
            if (f == null || !java.nio.file.Files.isRegularFile(f)) {
                imagedb.test.T.notTested("t_wire.c not found (" + path + "): the copies are not compared with their source");
                return;
            }
            String src = new String(java.nio.file.Files.readAllBytes(f), StandardCharsets.UTF_8);
            List<String> want = new ArrayList<>();
            for (Vec x : kVecs()) want.add("\"" + x.hex + "\"");
            for (String[] p : ScriptedTests.PINNED) {
                want.add("\"" + p[3] + "\"");
                want.add("\"" + p[4] + "\"");
            }
            for (String r : new String[] {"03 02", "02 0000000000000080", "06 ff3fd400014023ff", "07 006073cc0c448403", "09 0060d71d14000000",
                                          "08 c506f5ff", "08 a1c02c00", "04 02000000 c0af", "0d 01 c3", "0d 01 00"})
                want.add("\"" + r + "\"");
            int missing = 0;
            for (String w : want)
                if (!src.contains(w)) {
                    missing++;
                    imagedb.test.T.note("not in t_wire.c: " + w);
                }
            eq(0, missing, want.size() + " copied vectors found in " + f);
        });

        run("codec_decimal_range (t_wire.c 105-116)", () -> {
            BigInteger lim = BigInteger.TEN.pow(38);
            BigInteger[] ds = {lim.subtract(BigInteger.ONE), lim.subtract(BigInteger.ONE).negate(), lim, lim.negate()};
            for (int k = 0; k < 4; k++) {
                byte[] x = new byte[18];
                x[0] = Wire.T_DECIMAL;
                x[1] = 38;
                System.arraycopy(Value.i128(ds[k]), 0, x, 2, 16);
                eq(k < 2, valueVerdict(x) == 0, "DECIMAL " + ds[k] + " at scale 38");
                x[1] = 39;
                check(valueVerdict(x) != 0, "scale 39 refused");
            }
            // BigDecimal: never rounded; a negative scale made 0, trailing zeros past 38 places stripped
            eq("0500e8030000000000000000000000000000", hex(Value.decimal(new java.math.BigDecimal("1E+3")).encode()), "1E+3 as 1000 at scale 0");
            check(Value.decimal(new java.math.BigDecimal("1." + "0".repeat(40))).scale() == 0, "1.000... (40 places) stripped to scale 0");
            throwsIt(WireException.class, () -> Value.decimal(new java.math.BigDecimal("0." + "0".repeat(38) + "1")), "39 places refused");
            throwsIt(WireException.class, () -> Value.decimal(new java.math.BigDecimal(lim)), "10^38 refused");
        });

        run("codec_value_refused (t_wire.c 122-184)", () -> {
            String[] refused = {
                "03 02", "02 000000000000f07f", "02 000000000000f0ff", "02 010000000000f87f", "02 0000000000000080",
                "06 ff3fd400014023ff", "07 006073cc0c448403", "09 ffffffffffffffff", "09 0060d71d14000000", "08 c506f5ff",
                "08 a1c02c00", "04 01000000 ff", "04 01000000 00", "04 02000000 c0af", "0d 01 c3", "0d 01 00", "0e", "00",
                "8e", "ff", "",
            };
            for (String r : refused) check(valueVerdict(h(r)) != 0, "refused: " + r);
            String[] limit = {"04 00000100", "0b 00000100", "0d 40"}; // a length past its bound refused before its bytes
            for (String r : limit) eq(Wire.E_LIMIT, valueVerdict(h(r)), "LIMIT: " + r);
            // the encoder (the factories) refuses what the decoder would (t_wire.c 161-175)
            throwsIt(WireException.class, () -> Value.float64Bits(0x8000000000000000L), "-0");
            throwsIt(WireException.class, () -> Value.float64(Double.NaN), "NaN");
            throwsIt(WireException.class, () -> Value.float64(Double.POSITIVE_INFINITY), "infinity");
            throwsIt(WireException.class, () -> Value.textUtf8(new byte[] {(byte) 0xff}), "TEXT not UTF-8");
            throwsIt(WireException.class, () -> Value.textUtf8(new byte[65536]), "TEXT of 65,536");
            throwsIt(WireException.class, () -> Value.text("a\0b"), "TEXT with a NUL");
            throwsIt(WireException.class, () -> Value.text("\ud800"), "TEXT with an unpaired surrogate");
            throwsIt(WireException.class, () -> Value.enumUtf8(u("0123456789012345678901234567890123456789012345678901234567890123")), "a label of 64");
            throwsIt(WireException.class, () -> Value.decimal(BigInteger.ZERO, 39), "scale 39");
            throwsIt(WireException.class, () -> Value.date(2932897), "a DATE past 9999-12-31");
            throwsIt(WireException.class, () -> Value.timestamp(Long.MAX_VALUE), "a TIMESTAMP past 9999");
            throwsIt(WireException.class, () -> Value.uuid(new byte[15]), "a UUID of 15 bytes");
            throwsIt(WireException.class, () -> Value.nullOf(14), "a NULL of type 14");
            throwsIt(WireException.class, () -> Value.timestamp(java.time.LocalDateTime.of(2026, 1, 1, 0, 0, 0, 1)), "a nanosecond: never rounded");
            throwsIt(WireException.class, () -> Value.time(java.time.LocalTime.of(0, 0, 0, 999)), "a TIME's nanoseconds");
            throwsIt(WireException.class, () -> Value.timestamptz(java.time.Instant.parse("+10000-01-01T00:00:00Z")), "year 10000");
        });

        run("codec_utf8 (t_wire.c 186-220; Java's strict decoder the oracle)", () -> {
            byte[] s = {'a', 'b', (byte) 0xc3, (byte) 0xa9, 'c', (byte) 0xe2, (byte) 0x82, (byte) 0xac};
            int[][] cases = {{8, 100, 8}, {8, 8, 8}, {8, 7, 5}, {8, 6, 5}, {8, 5, 5}, {8, 3, 2}, {8, 0, 0}};
            for (int[] c : cases) eq(c[2], Utf8.fit(s, c[0], c[1]), "fit(" + c[0] + ", " + c[1] + ")");
            eq(2, Utf8.fit(new byte[] {'a', 'b', (byte) 0xff, 'c', 'd'}, 5, 5), "fit before 0xff");
            eq(2, Utf8.fit(new byte[] {'a', 'b', 0, 'c', 'd'}, 5, 5), "fit before NUL");
            int[] pick = {0x00, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xec, 0xed, 0xee,
                          0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xff};
            Random rnd = new Random(20261119);
            int disagree = 0;
            for (int round = 0; round < 200000; round++) {
                byte[] x = new byte[1 + rnd.nextInt(12)];
                for (int i = 0; i < x.length; i++) x[i] = (byte) (rnd.nextInt(4) != 0 ? pick[rnd.nextInt(pick.length)] : rnd.nextInt(256));
                boolean javaOk;
                try {
                    StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(x));
                    javaOk = true;
                } catch (CharacterCodingException e) {
                    javaOk = false;
                }
                boolean hasNul = false;
                for (byte b : x) hasNul |= b == 0;
                if (Utf8.valid(x) != (javaOk && !hasNul)) disagree++;
                int bad = Utf8.firstBad(x, 0, x.length);
                if (bad >= 0) { // everything before the first bad byte valid, and that byte's character not
                    if (!Utf8.valid(x, 0, bad)) disagree++;
                }
            }
            eq(0, disagree, "the validator against Java's strict UTF-8 decoder (no NUL), 200,000 drawn inputs");
        });

        run("codec_preauth (t_wire.c 223-398)", () -> {
            byte[] nonce = new byte[32];
            new Random(1).nextBytes(nonce);
            byte[] hb = PreAuth.hello(0, u("alice"), nonce);
            eq(112, hb.length, "a hello's 112 bytes");
            check(Arrays.equals(Arrays.copyOf(hb, 21), u("IMDBWIR1\u0001\0\0\0\0\0\0\0alice")), "the hello's head (t_wire.c 230)");
            for (int fl = 0; fl < 5; fl++) {
                final int f = fl;
                if (fl <= 2) eq(fl, (int) PreAuth.hello(fl, u("alice"), nonce)[12], "flags " + fl);
                else throwsIt(WireException.class, () -> PreAuth.hello(f, u("alice"), nonce), "flags " + fl + " refused");
            }
            throwsIt(WireException.class, () -> PreAuth.userBytes(""), "an empty name");
            throwsIt(WireException.class, () -> PreAuth.userBytes("a".repeat(64)), "64 bytes");
            eq(63, PreAuth.userBytes("a".repeat(63)).length, "63 bytes");
            eq(2, PreAuth.userBytes("é").length, "é");
            // the head every version keeps
            eq(1L, PreAuth.head(hb), "version 1");
            byte[] x = hb.clone();
            Buf.le32(x, 8, 7);
            eq(7L, PreAuth.head(x), "any version read");
            Buf.le32(x, 8, 0);
            eq(Wire.E_CORRUPT, code(throwsIt(WireException.class, () -> PreAuth.head(x), "version 0")), "version 0 as damage");
            Buf.le32(x, 8, 1);
            x[7] = '2';
            WireException later = throwsIt(WireException.class, () -> PreAuth.head(x), "IMDBWIR2");
            check(later != null && later.code() == Wire.E_UNSUPPORTED && later.getMessage().contains("IMDBWIR2"), "a later magic by name");
            x[0] = 'X';
            eq(Wire.E_CORRUPT, code(throwsIt(WireException.class, () -> PreAuth.head(x), "another magic")), "another magic as damage");
            // the challenge: its bounds (t_wire.c 350-369), its padding (370-372)
            int[][] sc = {{7, 4096, 0}, {8, 4096, 1}, {64, 4096, 1}, {65, 4096, 0}, {16, 999, 0}, {16, 1000, 1}, {16, 1000000, 1}, {16, 1000001, 0}};
            for (int[] c : sc) {
                byte[] ch = challenge(c[0], c[1]);
                boolean ok;
                try {
                    PreAuth.challenge(ch);
                    ok = true;
                } catch (WireException e) {
                    ok = false;
                }
                eq(c[2] == 1, ok, "challenge salt " + c[0] + " iterations " + c[1]);
            }
            byte[] ch = challenge(16, 4096);
            ch[13 + 16] = 1;
            throwsIt(WireException.class, () -> PreAuth.challenge(ch), "a byte in the salt's padding");
            byte[] ch2 = challenge(16, 4096);
            ch2[119] = 1;
            throwsIt(WireException.class, () -> PreAuth.challenge(ch2), "the tail's padding");
            byte[] ch3 = challenge(16, 4096);
            ch3[8] = 2;
            eq(Wire.E_UNSUPPORTED, code(throwsIt(WireException.class, () -> PreAuth.challenge(ch3), "a later version")), "a challenge of version 2 by name");
            // the verdict (t_wire.c 374-397)
            byte[] vb = new byte[36];
            new Random(2).nextBytes(vb);
            Buf.le32(vb, 0, 0);
            eq(0, PreAuth.verdict(vb).code, "accepted with a signature");
            vb[0] = 1;
            throwsIt(WireException.class, () -> PreAuth.verdict(vb), "a refusal with a signature");
            Arrays.fill(vb, 4, 36, (byte) 0);
            eq(1, PreAuth.verdict(vb).code, "refused");
            vb[0] = 2;
            eq(2, PreAuth.verdict(vb).code, "the binding type refused");
            vb[4] = 1;
            throwsIt(WireException.class, () -> PreAuth.verdict(vb), "verdict 2 with a signature");
            vb[4] = 0;
            vb[0] = 3;
            throwsIt(WireException.class, () -> PreAuth.verdict(vb), "verdict 3");
        });

        run("codec_scram_pinned (n1-design.md §4; t_wire.c 415-470)", () -> {
            byte[] n1 = new byte[32], salt = new byte[16], n2 = new byte[32];
            Arrays.fill(n1, (byte) 1);
            Arrays.fill(salt, (byte) 3);
            Arrays.fill(n2, (byte) 2);
            byte[] ch = challengeOf(salt, 4096, n2);
            PreAuth.Challenge c = PreAuth.challenge(ch);
            String[][] pinned = { // endpoint, flags, binding byte, ClientProof, ServerSignature (§4, t_wire.c 444-457)
                {"1", "1", "04", "28562c1bef99b0a917ecb28c1b32c22930f154f92c134b13fee7a64e8deb733e",
                 "5d3ef834c39e6c429d1f4e27993ba451a8b8e35322af9055abc1dd40e88ad322"},
                {"1", "2", "05", "1065f5e038b75f2671d831f5bd5d29f56d22a787f260db523bb986ef7c53f486",
                 "28fef60553090aae9b5f184bfc0cfb455e58261131da359f525a59f4dfaa9904"},
                {"2", "0", "00", "5ee7e7bd402f0c91e2399a84c3d544763bace50b44ea82a780e57130bb5405a7",
                 "82c9d498cc5fa830d26b29740244ecf4f343962f302a647150e9d74ea7588027"},
            };
            for (String[] p : pinned) {
                byte[] hb = PreAuth.hello(Integer.parseInt(p[1]), u("alice"), n1);
                byte[] bind = new byte[32];
                Arrays.fill(bind, (byte) Integer.parseInt(p[2], 16));
                byte[] am = PreAuth.authMessage(Integer.parseInt(p[0]), hb, ch, bind);
                // the AuthMessage laid out by hand (t_wire.c 429-434)
                byte[] want = new byte[279];
                System.arraycopy(u("IMDBWIR1-SCRAM"), 0, want, 0, 14);
                want[14] = (byte) Integer.parseInt(p[0]);
                System.arraycopy(hb, 0, want, 15, 112);
                System.arraycopy(ch, 0, want, 127, 120);
                System.arraycopy(bind, 0, want, 247, 32);
                check(Arrays.equals(am, want), "the AuthMessage's layout (flags " + p[1] + ")");
                byte[][] ps = PreAuth.scramClient("pencil".toCharArray(), c, am);
                eq(p[3], hex(ps[0]), "ClientProof, flags " + p[1]);
                eq(p[4], hex(ps[1]), "ServerSignature, flags " + p[1]);
            }
            // a password CREATE ROLE would refuse (t_wire.c 532-539)
            byte[] am = PreAuth.authMessage(2, PreAuth.hello(0, u("alice"), n1), ch, new byte[32]);
            for (String bad : new String[] {"", "a\u007f", "a\u001f", "é"})
                throwsIt(WireException.class, () -> PreAuth.scramClient(bad.toCharArray(), c, am), "password " + bad.length());
            throwsIt(WireException.class, () -> PreAuth.scramClient("a".repeat(1025).toCharArray(), c, am), "1,025 bytes");
            eq(32, PreAuth.scramClient("a".repeat(1024).toCharArray(), c, am)[0].length, "1,024 bytes");
        });

        run("codec_frames_server (t_wire.c 923-1089's server-type bodies; COPY_OUT ff00, PONG 00, COPY_IN, WARNING 0110: the driver's analogues of its client bodies)", () -> {
            // the head (t_wire.c 929-941), from the server's side
            check(headVerdict(0, Wire.ROWS) == Wire.E_LIMIT, "length 0");
            check(headVerdict(Wire.FRAME_MAX + 1, Wire.ROWS) == Wire.E_LIMIT, "16 MiB + 1");
            check(headVerdict(Wire.FRAME_MAX, Wire.ROWS) == 0, "16 MiB");
            for (int t : new int[] {0, 1, 12, 63, 75, 255}) check(headVerdict(5, t) != 0, "a server type " + t + " refused");
            Object[][] cases = {
                {Wire.COLUMNS, "0100 01ff 03 0000 0000", -1}, {Wire.COLUMNS, "0100 0161 0d 0000 0000 0100 01 80", -1},
                {Wire.DONE, "0100 ff 0000000000000000 00 00", -1}, {Wire.ERROR, "05000000 00000000 0100 00", -1},
                {Wire.WARNING, "0200 c0af", -1}, {Wire.ROWS, "01000000 00", -1}, {Wire.COLUMNS, "0000", -1},
                {Wire.COLUMNS, "0100 0161 05 2700 0000", -1}, {Wire.COLUMNS, "0100 0161 05 0200 0300", -1},
                {Wire.COLUMNS, "0100 0161 05 2600 2600", 0}, {Wire.COLUMNS, "0100 0161 01 0800 0000", -1},
                {Wire.COLUMNS, "0100 0161 01 1000 0000", 0}, {Wire.COLUMNS, "0100 0161 03 0100 0000", -1},
                {Wire.COLUMNS, "0100 0161 00 0000 0000", 0}, {Wire.COLUMNS, "0100 0161 00 0100 0000", -1},
                {Wire.COLUMNS, "0100 0161 05 0000 2600", 0}, {Wire.COLUMNS, "0100 0161 05 0000 2700", -1},
                {Wire.COLUMNS, "0100 0161 0e 0000 0000", -1}, {Wire.COLUMNS, "0100 0161 0d 0000 0000 ffff", -1},
                {Wire.COLUMNS, "0100 0161 0d 0000 0000 0104", -1}, {Wire.COLUMNS, "0100 0161 0d 0000 0000 0100 00", 0},
                {Wire.COLUMNS, "0100 0161 0d 0000 0000 0100 40", Wire.E_LIMIT}, {Wire.COLUMNS, "0100 0161 0d 0100 0000 0100 00", -1},
                {Wire.COLUMNS, "0100 0165 0d 0000 0000 0200 0161 0161", Wire.E_CORRUPT}, // t_wire.c 856: a label twice
                {Wire.DONE, "0000 0000000000000000 02 00", -1}, {Wire.DONE, "0000 0000000000000000 00 00", 0},
                {Wire.DONE, "0000 ffffffffffffffff 00 00", 0}, {Wire.DONE, "0000 00 00", -1},
                {Wire.ERROR, "05000000 00100000 0000", -1}, {Wire.ERROR, "00000000 00000000 0000", -1},
                {Wire.ERROR, "05000000 ff0f0000 0000", 0}, {Wire.READY, "03", -1}, {Wire.READY, "", -1},
                {Wire.KILL_DONE, "01 0100000000000000", 0}, {Wire.KILL_DONE, "02 0100000000000000", -1},
                {Wire.KILL_DONE, "03 0100000000000000", -1}, {Wire.KILL_DONE, "00 0000000000000000", -1},
                {Wire.SESSIONS_LIST, "00000000", 0},
                {Wire.SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 00", 0},
                {Wire.SESSIONS_LIST, "01000000 0000000000000000 01000000 01 00 0000000000000000 00", -1},
                {Wire.SESSIONS_LIST, "01000000 0100000000000000 00000000 01 00 0000000000000000 00", -1},
                {Wire.SESSIONS_LIST, "01000000 0100000000000000 01000000 03 00 0000000000000000 00", -1},
                {Wire.SESSIONS_LIST, "01000000 0100000000000000 01000000 01 04 0000000000000000 00", -1},
                {Wire.SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 40", -1},
                {Wire.SESSIONS_LIST, "01000000 0100000000000000 01000000 01 00 0000000000000000 01 ff", -1},
                {Wire.SESSIONS_LIST, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 0200000000000000 01000000 01 00 0000000000000000 00", -1},
                {Wire.SESSIONS_LIST, "02000000 0200000000000000 01000000 01 00 0000000000000000 00 0100000000000000 01000000 01 00 0000000000000000 00", -1},
                {Wire.SESSIONS_LIST, "02000000 0100000000000000 01000000 01 00 0000000000000000 00", -1},
                {Wire.SESSIONS_LIST, "01000100 0100000000000000 01000000 01 00 0000000000000000 00", -1},
                {Wire.COPY_OUT, "", -1}, {Wire.COPY_OUT, "ff00", 0}, {Wire.PONG, "00", -1}, {Wire.PONG, "", 0},
                {Wire.COPY_IN, "", 0}, {Wire.WARNING, "0110", Wire.E_LIMIT},
            };
            for (Object[] c : cases) {
                int got = bodyVerdict((Integer) c[0], (String) c[1], null);
                int want = (Integer) c[2];
                check(want == -1 ? got != 0 : got == want, Wire.frameName((Integer) c[0]) + " " + c[1] + ": want " + want + ", got " + got);
            }
            String z32 = "00".repeat(32), z16 = "00".repeat(16);
            eq(0, bodyVerdict(Wire.DONE, "0000 0000000000000000 01 0000000000000000 " + z32 + " " + z32 + " 0100000000000000 01" + z32.substring(2) + " " + z16 + " 00 00", null), "a read point (t_wire.c 999)");
            eq(0, bodyVerdict(Wire.DONE, "0000 0000000000000000 01 0000000000000000 " + z32 + " " + z32 + " 0100000000000000 " + z32 + " " + z16 + " 01 00", null), "own writes");
            check(bodyVerdict(Wire.DONE, "0000 0000000000000000 01 0000000000000000 " + z32 + " " + z32 + " 0100000000000000 " + z32 + " " + z16 + " 02 00", null) != 0, "own 2");
            check(bodyVerdict(Wire.DONE, "0000 0000000000000000 00 01 0000000000000000 " + z32, null) != 0, "a write at commit 0");
            eq(Wire.E_LIMIT, bodyVerdict(Wire.DONE, "0002 " + "00".repeat(512) + " 00 00", null), "a status of 512 bytes");
            // 1,024 distinct labels taken, 1,025 refused (t_wire.c 1044-1073)
            for (int nl = 1024; nl <= 1025; nl++) {
                Buf b = new Buf();
                b.put(new byte[] {1, 0, 1, 'e', Wire.T_ENUM, 0, 0, 0, 0});
                b.u16(nl);
                for (int i = 0; i < nl; i++) {
                    b.u8(3);
                    b.put(new byte[] {(byte) ('a' + i / 676), (byte) ('a' + i / 26 % 26), (byte) ('a' + i % 26)});
                }
                eq(nl == 1024, bodyVerdict(Wire.COLUMNS, hex(b.bytes()), null) == 0, nl + " labels");
            }
            // a count past its bytes refused (t_wire.c 1075-1087)
            check(bodyVerdict(Wire.COLUMNS, "0001 0161 01 0000 0000", null) != 0, "256 columns in 8 bytes");
            check(bodyVerdict(Wire.COLUMNS, "0100 0161 0d 0000 0000 0004", null) != 0, "1,024 labels in none");
        });

        run("codec_rows_fit (t_wire.c 766-864)", () -> {
            // the samples' COLUMNS (t_wire.c 594-607): id INTEGER, amount DECIMAL(38,6), name VARCHAR(12), mood ENUM('', 'x', 'é')
            String cols = "0400" + "026964 01 2000 0000" + "06616d6f756e74 05 2600 0600" + "046e616d65 04 0c00 0000"
                    + "046d6f6f64 0d 0000 0000 0300 00 0178 02c3a9";
            Msg.Columns cm = (Msg.Columns) Frames.decode(Wire.COLUMNS, h(cols), null);
            eq(4, cm.columns.size(), "four columns");
            eq(Arrays.asList("", "x", "é"), cm.columns.get(3).labels, "the labels in order");
            BigInteger lim = BigInteger.TEN.pow(38);
            Object[][] cases = { // column, value, fits (t_wire.c 778-796)
                {0, Value.int64(Integer.MAX_VALUE), true}, {0, Value.int64(Integer.MAX_VALUE + 1L), false},
                {0, Value.int64(Integer.MIN_VALUE - 1L), false}, {0, Value.timestamp(1), false},
                {0, Value.nullOf(Wire.T_INT64), true}, {0, Value.nullOf(Wire.T_TEXT), false}, {0, Value.nullOf(Wire.T_NONE), false},
                {1, Value.decimal(lim.subtract(BigInteger.ONE), 6), true}, {1, Value.decimal(BigInteger.ONE, 5), false},
                {1, Value.int64(1), false}, {2, Value.text("é".repeat(12)), true}, {2, Value.text("0123456789abc"), false},
                {2, Value.bytea(new byte[] {'a'}), false}, {3, Value.enumLabel("é"), true}, {3, Value.enumLabel("y"), false},
                {3, Value.enumLabel("xx"), false}, {3, Value.text("x"), false},
            };
            for (Object[] c : cases) {
                int col = (Integer) c[0];
                Value v = (Value) c[1];
                eq(c[2], cm.columns.get(col).fits(v), "fits: column " + col + " " + v);
                Value[] row = {Value.nullOf(Wire.T_INT64), Value.nullOf(Wire.T_DECIMAL), Value.nullOf(Wire.T_TEXT), Value.nullOf(Wire.T_ENUM)};
                row[col] = v;
                Buf b = new Buf();
                b.u32(1);
                for (Value x : row) x.encode(b);
                eq((Boolean) c[2], bodyVerdict(Wire.ROWS, hex(b.bytes()), cm) == 0, "a ROWS holding it: column " + col + " " + v);
            }
            Msg.Rows r = (Msg.Rows) Frames.decode(Wire.ROWS, h("01000000 81 85 84 8d"), cm);
            check(r.rows.size() == 1 && r.rows.get(0)[3].isNull && r.rows.get(0)[3].type == Wire.T_ENUM, "a row of typed NULLs");
            check(bodyVerdict(Wire.ROWS, "00000000", cm) != 0, "a ROWS of no row");
            check(bodyVerdict(Wire.ROWS, "02000000 81 85 84 8d", cm) != 0, "a ROWS of two rows holding one");
            check(bodyVerdict(Wire.ROWS, "01000000 81 85 84", cm) != 0, "a row cut short");
            // a column of no known type takes any value; a SMALLINT's width; a DECIMAL(5,2)'s digits (t_wire.c 822-839)
            Msg.Columns none = (Msg.Columns) Frames.decode(Wire.COLUMNS, h("0100 0178 00 0000 0000"), null);
            for (String v : new String[] {"01 0100000000000000", "0d 01 71", "80", "88"})
                eq(0, bodyVerdict(Wire.ROWS, "01000000 " + v, none), "any value under type 0: " + v);
            check(bodyVerdict(Wire.ROWS, "01000000 0302", none) != 0, "a BOOL of 2 under type 0");
            Msg.Columns sm = (Msg.Columns) Frames.decode(Wire.COLUMNS, h("0100 0173 01 1000 0000"), null);
            check(sm.columns.get(0).fits(Value.int64(Short.MAX_VALUE)) && !sm.columns.get(0).fits(Value.int64(Short.MAX_VALUE + 1)), "SMALLINT");
            Msg.Columns d52 = (Msg.Columns) Frames.decode(Wire.COLUMNS, h("0100 0164 05 0500 0200"), null);
            check(d52.columns.get(0).fits(Value.decimal(BigInteger.valueOf(-99999), 2))
                    && !d52.columns.get(0).fits(Value.decimal(BigInteger.valueOf(100000), 2)), "DECIMAL(5,2)");
        });

        run("codec_frames_client (t_wire.c 942-1021: the encoders give the bodies t_wire's decoder takes)", () -> {
            eq("0c000000" + "01" + "01000000 01000000 61 0000".replace(" ", ""), hex(Frames.query(Collections.singletonList(new Frames.Stmt("a", null)))), "QUERY a (t_wire.c 947)");
            eq("0d000000" + "01" + "01000000 01000000 61 0100 81".replace(" ", ""),
               hex(Frames.query(Collections.singletonList(new Frames.Stmt("a", Collections.singletonList(Value.nullOf(Wire.T_INT64)))))), "QUERY a $1 NULL INT64 (948)");
            eq("0d000000" + "01" + "01000000 01000000 61 0100 8d".replace(" ", ""),
               hex(Frames.query(Collections.singletonList(new Frames.Stmt("a", Collections.singletonList(Value.nullOf(Wire.T_ENUM)))))), "a NULL ENUM: the one ENUM parameter (951)");
            throwsIt(WireException.class, () -> Frames.query(Collections.singletonList(new Frames.Stmt("a", Collections.singletonList(Value.enumLabel("a"))))), "an ENUM parameter refused (950)");
            eq("0a000000" + "03" + "0170 01000000 0100 80".replace(" ", ""),
               hex(Frames.execute("p", Collections.singletonList(Collections.singletonList(Value.nullOf(Wire.T_NONE))))), "EXECUTE p, one NULL of no type (967)");
            eq("08000000" + "02" + "0170 01000000 61".replace(" ", ""), hex(Frames.prepare("p", "a")), "PREPARE p a (970)");
            eq("0a000000" + "0c" + "01 0100000000000000".replace(" ", ""), hex(Frames.kill(1, 1)), "KILL cancel 1 (1016)");
            eq("0a000000" + "0c" + "02 ffffffffffffffff".replace(" ", ""), hex(Frames.kill(2, -1)), "KILL terminate 2^64-1");
            eq("03000000" + "04" + "0170", hex(Frames.deallocate("p")), "DEALLOCATE p");
            eq("0100000008", hex(Frames.empty(Wire.CANCEL)), "CANCEL");
            eq("0100000009", hex(Frames.empty(Wire.PING)), "PING");
            eq("010000000b", hex(Frames.empty(Wire.SESSIONS)), "SESSIONS");
            eq("0300000005ff00", hex(Frames.copyData(new byte[] {(byte) 0xff, 0}, 0, 2)), "COPY_DATA raw (964)");
            throwsIt(WireException.class, () -> Frames.query(new ArrayList<>()), "no statement (942)");
            throwsIt(WireException.class, () -> Frames.query(Collections.singletonList(new Frames.Stmt("", null))), "an empty statement (945)");
            throwsIt(WireException.class, () -> Frames.prepare("n".repeat(64), "a"), "a name of 64 (972)");
            throwsIt(WireException.class, () -> Frames.prepare("", "a"), "an empty name (969)");
            throwsIt(WireException.class, () -> Frames.kill(3, 1), "kind 3 (1018)");
            throwsIt(WireException.class, () -> Frames.kill(2, 0), "session 0 (1019)");
            throwsIt(WireException.class, () -> Frames.copyData(new byte[0], 0, 0), "an empty COPY piece (1041)");
            List<Value> many = new ArrayList<>();
            for (int i = 0; i < 257; i++) many.add(Value.nullOf(Wire.T_NONE));
            throwsIt(WireException.class, () -> Frames.query(Collections.singletonList(new Frames.Stmt("a", many))), "257 values (952)");
            List<List<Value>> sets = new ArrayList<>();
            sets.add(Collections.singletonList(Value.int64(1)));
            sets.add(Arrays.asList(Value.int64(1), Value.int64(2)));
            throwsIt(WireException.class, () -> Frames.execute("p", sets), "sets of two counts");
            byte[] cf = Frames.copyFail("é".repeat(3000)); // 6,000 bytes: cut at a character to 4,096
            eq(4096, (cf[5] & 0xff) | (cf[6] & 0xff) << 8, "COPY_FAIL's reason cut at 4,096 bytes");
        });

        run("codec_one_encoding (every byte of every server sample flipped three ways: what decodes re-encodes to itself)", () -> {
            List<byte[][]> samples = ServerEncoder.samples();
            int took = 0, refused = 0, bad = 0;
            Msg.Columns cols = (Msg.Columns) Frames.decode(Wire.COLUMNS, samples.get(0)[1], null);
            for (byte[][] s : samples) {
                int type = s[0][0];
                byte[] body = s[1];
                try { // the sample itself
                    Msg m = Frames.decode(type, body, cols);
                    if (!Arrays.equals(ServerEncoder.encode(m, cols), body)) bad++;
                } catch (WireException x) {
                    bad++;
                }
                for (int i = 0; i < body.length; i++)
                    for (int f : new int[] {0x01, 0x80, 0xff}) {
                        byte[] y = body.clone();
                        y[i] ^= (byte) f;
                        Msg m;
                        try {
                            m = Frames.decode(type, y, cols);
                        } catch (WireException x) {
                            refused++;
                            continue;
                        }
                        took++;
                        if (!Arrays.equals(ServerEncoder.encode(m, cols), y)) {
                            bad++;
                            if (bad < 5) imagedb.test.T.note("two encodings: " + Wire.frameName(type) + " byte " + i + " ^ " + f);
                        }
                    }
                for (int cut = 0; cut < body.length; cut++) { // every cut refused but COPY_OUT's raw bytes
                    try {
                        Frames.decode(type, Arrays.copyOf(body, cut), cols);
                        if (type != Wire.COPY_OUT || cut == 0) bad++;
                    } catch (WireException x) {
                        // refused
                    }
                }
            }
            eq(0, bad, "decoded flips that encode otherwise, or cuts taken");
            imagedb.test.T.note(samples.size() + " samples: " + took + " flips taken (each re-encoded to itself), " + refused + " refused");
        });
    }

    static byte[] challenge(int saltLen, int iter) {
        byte[] c = new byte[120];
        System.arraycopy(Wire.MAGIC, 0, c, 0, 8);
        Buf.le32(c, 8, 1);
        c[12] = (byte) saltLen;
        for (int i = 0; i < Math.min(saltLen, 64); i++) c[13 + i] = (byte) (i + 1);
        Buf.le32(c, 13 + 64, iter);
        for (int i = 0; i < 32; i++) c[81 + i] = (byte) (0x40 + i);
        return c;
    }

    static byte[] challengeOf(byte[] salt, int iter, byte[] nonce) {
        byte[] c = new byte[120];
        System.arraycopy(Wire.MAGIC, 0, c, 0, 8);
        Buf.le32(c, 8, 1);
        c[12] = (byte) salt.length;
        System.arraycopy(salt, 0, c, 13, salt.length);
        Buf.le32(c, 77, iter);
        System.arraycopy(nonce, 0, c, 81, 32);
        return c;
    }

    static int headVerdict(long len, int type) {
        byte[] hd = new byte[5];
        Buf.le32(hd, 0, len);
        hd[4] = (byte) type;
        try {
            Frames.head(hd);
            return 0;
        } catch (WireException x) {
            return x.code();
        }
    }

    static int bodyVerdict(int type, String hexBody, Msg.Columns cols) {
        try {
            Frames.decode(type, h(hexBody), cols);
            return 0;
        } catch (WireException x) {
            return x.code();
        }
    }
}
