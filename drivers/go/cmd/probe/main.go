// Command probe runs one statement through the Go driver, an acceptance probe:
//
//	probe SOCKET PASSWORD SQL
//
// It connects over the server's Unix-domain socket as the role admin, runs the statement, prints its columns (a line of
// names, tab-separated) and rows (one a line, NULL for a NULL), then its DONE's status and count, and exits 0; or prints
// the driver's error on stderr and exits 1.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"imagedb.dev/imagedb"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: probe SOCKET PASSWORD SQL")
		os.Exit(2)
	}
	ctx := context.Background()
	c, err := imagedb.Connect(ctx, imagedb.Config{Socket: os.Args[1], User: "admin", Password: os.Args[2]})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer c.Close()
	rows, err := c.Query(ctx, os.Args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if cols := rows.Columns(); cols != nil {
		names := make([]string, len(cols))
		for i, col := range cols {
			names[i] = col.Name
		}
		fmt.Println(strings.Join(names, "\t"))
	}
	for rows.Next() {
		vals := rows.Values()
		cells := make([]string, len(vals))
		for i, v := range vals {
			if v == nil {
				cells[i] = "NULL"
			} else {
				cells[i] = fmt.Sprint(v)
			}
		}
		fmt.Println(strings.Join(cells, "\t"))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rows.Close()
	if d := rows.Done(); d != nil {
		fmt.Printf("-- %s (%d)\n", d.Status, d.Count)
	}
}
