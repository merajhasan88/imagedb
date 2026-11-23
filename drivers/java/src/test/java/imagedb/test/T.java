package imagedb.test;

import java.util.ArrayList;
import java.util.List;

/** the tests' own small runner: named tests, checks counted, a failure reported with its place and the test going on */
public final class T {
    private T() {}

    public interface Body {
        void run() throws Exception;
    }

    static int tests, failedTests, checks, failedChecks, skipped;
    static String current;
    static final List<String> failures = new ArrayList<>();
    static final List<String> notTested = new ArrayList<>();
    static String filter;

    public static void check(boolean ok, String what) {
        checks++;
        if (ok) return;
        failedChecks++;
        StackTraceElement at = null;
        for (StackTraceElement e : new Throwable().getStackTrace())
            if (!e.getClassName().equals(T.class.getName())) {
                at = e;
                break;
            }
        String m = current + ": " + what + (at != null ? " (" + at.getFileName() + ":" + at.getLineNumber() + ")" : "");
        failures.add(m);
        System.out.println("    FAIL " + m);
    }

    public static void eq(Object want, Object got, String what) {
        boolean ok = want == null ? got == null : want.equals(got);
        check(ok, what + ": want " + want + ", got " + got);
    }

    /** the body throws, and the throwable passes test */
    public static <X extends Throwable> X throwsIt(Class<X> type, Body b, String what) {
        try {
            b.run();
        } catch (Throwable x) {
            if (type.isInstance(x)) {
                checks++;
                return type.cast(x);
            }
            check(false, what + ": threw " + x);
            return null;
        }
        check(false, what + ": did not throw");
        return null;
    }

    public static void note(String s) { System.out.println("    " + s); }

    public static void notTested(String s) {
        notTested.add(current + ": " + s);
        System.out.println("    NOT TESTED: " + s);
    }

    public static void run(String name, Body b) {
        if (filter != null && !name.contains(filter)) return;
        tests++;
        current = name;
        int before = failedChecks;
        long t0 = System.nanoTime();
        System.out.println("  " + name);
        try {
            b.run();
        } catch (Throwable x) {
            failedChecks++;
            failures.add(name + ": threw " + x);
            System.out.println("    FAIL threw " + x);
            x.printStackTrace(System.out);
        }
        long ms = (System.nanoTime() - t0) / 1_000_000;
        if (failedChecks != before) failedTests++;
        System.out.println("    " + (failedChecks == before ? "ok" : "FAILED") + " (" + ms + " ms)");
    }

    /** the summary line; the exit status */
    public static int summary(String suite) {
        System.out.println(suite + ": " + tests + " tests, " + (tests - failedTests) + " passed, " + failedTests + " failed; "
                + checks + " checks, " + failedChecks + " failed");
        for (String f : failures) System.out.println("  failure: " + f);
        for (String n : notTested) System.out.println("  not tested: " + n);
        return failedTests == 0 && failedChecks == 0 ? 0 : 1;
    }
}
