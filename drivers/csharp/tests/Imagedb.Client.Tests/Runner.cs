using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace Imagedb.Client.Tests;

/// <summary>A test's failure: the check that did not hold.</summary>
public sealed class CheckFailed : Exception
{
    public CheckFailed(string m) : base(m) { }
}

/// <summary>The checks a test makes (no framework package: the base class library alone).</summary>
public static class T
{
    private static int _checks; // tests run one at a time; their tasks may hop threads
    public static int Checks => _checks;
    public static void ResetChecks() => _checks = 0;

    public static void Check(bool cond, string what)
    {
        System.Threading.Interlocked.Increment(ref _checks);
        if (!cond) throw new CheckFailed(what);
    }

    public static void Eq<TV>(TV expected, TV actual, string what)
    {
        System.Threading.Interlocked.Increment(ref _checks);
        if (!EqualityComparer<TV>.Default.Equals(expected, actual))
            throw new CheckFailed($"{what}: expected <{expected}>, got <{actual}>");
    }

    public static void Bytes(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string what)
    {
        System.Threading.Interlocked.Increment(ref _checks);
        if (!expected.SequenceEqual(actual))
            throw new CheckFailed($"{what}: expected {Convert.ToHexString(expected)}, got {Convert.ToHexString(actual)}");
    }

    public static TE Throws<TE>(Action a, string what) where TE : Exception
    {
        System.Threading.Interlocked.Increment(ref _checks);
        try
        {
            a();
        }
        catch (TE e)
        {
            return e;
        }
        catch (Exception e)
        {
            throw new CheckFailed($"{what}: expected {typeof(TE).Name}, got {e.GetType().Name}: {e.Message}");
        }
        throw new CheckFailed($"{what}: expected {typeof(TE).Name}, nothing thrown");
    }

    public static async Task<TE> ThrowsAsync<TE>(Func<Task> a, string what) where TE : Exception
    {
        System.Threading.Interlocked.Increment(ref _checks);
        try
        {
            await a();
        }
        catch (TE e)
        {
            return e;
        }
        catch (Exception e)
        {
            throw new CheckFailed($"{what}: expected {typeof(TE).Name}, got {e.GetType().Name}: {e.Message}");
        }
        throw new CheckFailed($"{what}: expected {typeof(TE).Name}, nothing thrown");
    }

    public static byte[] Hex(string h) => Convert.FromHexString(h.Replace(" ", "", StringComparison.Ordinal));
}

public sealed record TestCase(string Group, string Name, Func<Task> Run);

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var groups = args.Length > 0 ? new HashSet<string>(args[0].Split(','), StringComparer.Ordinal) : new HashSet<string> { "codec" };
        string? only = args.Length > 1 ? args[1] : null;
        var all = new List<TestCase>();
        all.AddRange(CodecTests.All());
        all.AddRange(MockTests.All());
        all.AddRange(LiveTests.All());
        all.AddRange(AdoTests.All()); // after LiveTests: its live tests read copy_in_1m_rows[sock]'s table
        int passed = 0, failed = 0, checks = 0;
        var failures = new List<string>();
        foreach (var tc in all.Where(t => groups.Contains(t.Group) && (only == null || t.Name.Contains(only, StringComparison.Ordinal))))
        {
            T.ResetChecks();
            var sw = Stopwatch.StartNew();
            try
            {
                await tc.Run().WaitAsync(TimeSpan.FromMinutes(5));
                passed++;
                Console.WriteLine($"ok   {tc.Group}/{tc.Name} ({T.Checks} checks, {sw.ElapsedMilliseconds} ms)");
            }
            catch (Exception e)
            {
                failed++;
                string m = e is CheckFailed ? e.Message : e.ToString();
                failures.Add($"{tc.Group}/{tc.Name}: {m}");
                Console.WriteLine($"FAIL {tc.Group}/{tc.Name} ({sw.ElapsedMilliseconds} ms): {m}");
            }
            checks += T.Checks;
        }
        Console.WriteLine($"csharp driver [{string.Join(",", groups)}]: {passed} passed, {failed} failed, {checks} checks");
        foreach (var f in failures) Console.WriteLine("  FAILED " + f);
        return failed == 0 && passed > 0 ? 0 : 1;
    }
}
