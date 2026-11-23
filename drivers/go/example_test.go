package imagedb_test

// Examples: compiled with the tests (no Output comment: they need a server, so go test does not run them).

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"imagedb.dev/imagedb"
)

// The native client over TCP with TLS 1.3, the server's key pinned (imagedb-server cert prints the pin).
func ExampleConnect() {
	pin, _ := imagedb.ParsePin("11730bc0017997058a6e32fbf05de0f8ade3245750e782a68ca1e564b481602c")
	ctx := context.Background()
	c, err := imagedb.Connect(ctx, imagedb.Config{Addr: "127.0.0.1:5433", Pin: pin, User: "admin", Password: "secret"})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	rows, err := c.Query(ctx, "SELECT id, amount, at FROM payments WHERE id > $1", 10)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var amount imagedb.Decimal // exact: 38 digits
		var at time.Time           // TIMESTAMPTZ: UTC, microseconds
		if err := rows.Scan(&id, &amount, &at); err != nil {
			log.Fatal(err)
		}
		fmt.Println(id, amount, at)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("read at commit", rows.Done().Read.Commit)
}

// A batch: an ERROR ends it, its Index naming the statement that failed.
func ExampleConn_Batch() {
	ctx := context.Background()
	c, err := imagedb.Connect(ctx, imagedb.Config{Socket: "/run/imagedb/s.sock", User: "admin", Password: "secret"})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	res, err := c.Batch(ctx,
		imagedb.Statement{SQL: "INSERT INTO t VALUES ($1, $2)", Args: []any{1, "one"}},
		imagedb.Statement{SQL: "INSERT INTO t VALUES ($1, $2)", Args: []any{2, imagedb.NullOf(imagedb.TypeText)}})
	var e *imagedb.Error
	if err != nil && !errorsAs(err, &e) {
		log.Fatal(err)
	}
	fmt.Println(len(res), "ran; failed at", e)
}

// COPY both ways.
func ExampleConn_CopyFrom() {
	ctx := context.Background()
	c, err := imagedb.Connect(ctx, imagedb.Config{Socket: "/run/imagedb/s.sock", User: "admin", Password: "secret"})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	f, _ := os.Open("rows.csv")
	defer f.Close()
	if _, err := c.CopyFrom(ctx, "COPY t FROM STDIN", f); err != nil {
		log.Fatal(err)
	}
	if _, err := c.CopyTo(ctx, "COPY t TO STDOUT", os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// database/sql, by DSN (the CA file checks the host against the certificate's names).
func Example_databaseSQL() {
	db, err := sql.Open("imagedb", "imagedb://admin:secret@localhost:5433/?ca=/etc/imagedb/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow("SELECT COUNT(*) FROM t WHERE k > $1", 5).Scan(&n); err != nil {
		log.Fatal(err)
	}
	fmt.Println(n)
}

func errorsAs(err error, e **imagedb.Error) bool {
	x, ok := err.(*imagedb.Error)
	*e = x
	return ok
}
