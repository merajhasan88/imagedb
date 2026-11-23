// The acceptance probe: Imagedb.Probe SOCKET PASSWORD SQL. Connects over the server's Unix-domain socket as the role
// admin, runs the one statement, prints its columns (a line of names, tab-separated), its rows (each value's text:
// ImdbValue.ToString, NULL as NULL) and its status and count; exit 0. Any error: the driver's words on stderr, exit 1.
using System;
using System.Linq;
using System.Threading.Tasks;
using Imagedb.Client;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 3)
        {
            Console.Error.WriteLine("usage: Imagedb.Probe SOCKET PASSWORD SQL");
            return 2;
        }
        try
        {
            await using var c = await ImdbConnection.ConnectAsync(new ImdbConnectOptions
            {
                SocketPath = args[0], User = "admin", Password = args[1],
            });
            var r = await c.QueryAsync(args[2]);
            if (r.ReturnsRows)
            {
                Console.WriteLine(string.Join("\t", r.Columns.Select(col => col.Name)));
                foreach (var row in r.Rows) Console.WriteLine(string.Join("\t", row.Values.Select(v => v.ToString())));
            }
            Console.WriteLine($"-- {r.Status} (count {r.Count})");
            return 0;
        }
        catch (Exception e) when (e is ImdbException or ArgumentException or System.Net.Sockets.SocketException or System.IO.IOException)
        {
            string code = e is ImdbException ie ? $" {ie.Code}" : "";
            Console.Error.WriteLine($"imagedb probe: error{code}: {e.Message}");
            return 1;
        }
    }
}
