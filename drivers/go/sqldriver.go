package imagedb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"

	"imagedb.dev/imagedb/wire"
)

func init() { sql.Register("imagedb", &Driver{}) }

// Driver is database/sql's driver, registered as "imagedb". A DSN:
//
//	imagedb:///path/to/socket?user=NAME&password=PW                     the Unix-domain socket
//	imagedb://NAME:PW@host:port/?ca=/path/ca.crt                        TCP with TLS, the CA (the host checked)
//	imagedb://NAME:PW@host:port/?pin=64HEX[&binding=tls-server-end-point] TCP with TLS, the pinned key
//
// and connect_timeout, read_timeout, cancel_wait (Go durations). Placeholders are $1, $2, ... (ordinal only).
type Driver struct{}

// Open opens a connection from a DSN.
func (d *Driver) Open(dsn string) (driver.Conn, error) {
	c, err := d.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

// OpenConnector parses the DSN once.
func (d *Driver) OpenConnector(dsn string) (driver.Connector, error) {
	cfg, err := ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	return &connector{cfg: cfg, d: d}, nil
}

// NewConnector is a database/sql connector for a Config (sql.OpenDB(imagedb.NewConnector(cfg))).
func NewConnector(cfg Config) driver.Connector { return &connector{cfg: cfg, d: &Driver{}} }

// ParseDSN reads a DSN into a Config (strict: an unknown parameter is refused).
func ParseDSN(dsn string) (Config, error) {
	var cfg Config
	u, err := url.Parse(dsn)
	if err != nil {
		return cfg, fmt.Errorf("imagedb: a DSN: %w", err)
	}
	if u.Scheme != "imagedb" {
		return cfg, errors.New("imagedb: a DSN begins imagedb://")
	}
	if u.Host == "" {
		cfg.Socket = u.Path
	} else {
		cfg.Addr = u.Host
		if u.Path != "" && u.Path != "/" {
			return cfg, errors.New("imagedb: a TCP DSN has no path")
		}
	}
	if u.User != nil {
		cfg.User = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}
	for k, vs := range u.Query() {
		if len(vs) != 1 {
			return cfg, fmt.Errorf("imagedb: the DSN's %s given %d times", k, len(vs))
		}
		v := vs[0]
		switch k {
		case "user":
			cfg.User = v
		case "password":
			cfg.Password = v
		case "socket":
			cfg.Socket = v
		case "ca":
			cfg.CAFile = v
		case "pin":
			if cfg.Pin, err = ParsePin(v); err != nil {
				return cfg, err
			}
		case "binding":
			switch v {
			case "exporter", "tls-exporter":
				cfg.Binding = BindingExporter
			case "endpoint", "tls-server-end-point":
				cfg.Binding = BindingEndpoint
			default:
				return cfg, fmt.Errorf("imagedb: binding=%s: tls-exporter or tls-server-end-point", v)
			}
		case "connect_timeout", "read_timeout", "cancel_wait":
			d, err := time.ParseDuration(v)
			if err != nil || d < 0 {
				return cfg, fmt.Errorf("imagedb: %s=%s: a duration", k, v)
			}
			switch k {
			case "connect_timeout":
				cfg.ConnectTimeout = d
			case "read_timeout":
				cfg.ReadTimeout = d
			default:
				cfg.CancelWait = d
			}
		default:
			return cfg, fmt.Errorf("imagedb: the DSN's %s: no such parameter", k)
		}
	}
	if cfg.Socket != "" && cfg.Addr != "" {
		return cfg, errors.New("imagedb: a DSN names a socket or a host, not both")
	}
	return cfg, nil
}

type connector struct {
	cfg Config
	d   *Driver
}

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	cn, err := Connect(ctx, c.cfg)
	if err != nil {
		return nil, err
	}
	return &sqlConn{c: cn}, nil
}

func (c *connector) Driver() driver.Driver { return c.d }

// sqlConn is a Conn as database/sql's driver.Conn.
type sqlConn struct {
	c     *Conn
	nstmt atomic.Uint64
}

var (
	_ driver.Conn               = (*sqlConn)(nil)
	_ driver.ConnPrepareContext = (*sqlConn)(nil)
	_ driver.ConnBeginTx        = (*sqlConn)(nil)
	_ driver.ExecerContext      = (*sqlConn)(nil)
	_ driver.QueryerContext     = (*sqlConn)(nil)
	_ driver.Pinger             = (*sqlConn)(nil)
	_ driver.SessionResetter    = (*sqlConn)(nil)
	_ driver.Validator          = (*sqlConn)(nil)
	_ driver.NamedValueChecker  = (*sqlConn)(nil)
)

// Raw is the native Conn under a database/sql connection (sql.Conn.Raw(func(dc any) error { c := dc.(interface{
// Native() *imagedb.Conn }).Native() ... })).
func (s *sqlConn) Native() *Conn { return s.c }

func (s *sqlConn) Prepare(query string) (driver.Stmt, error) {
	return s.PrepareContext(context.Background(), query)
}

func (s *sqlConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if s.c.failed() != nil {
		return nil, driver.ErrBadConn // nothing sent: database/sql takes another connection
	}
	name := "go_stmt_" + strconv.FormatUint(s.nstmt.Add(1), 10)
	if err := s.c.Prepare(ctx, name, query); err != nil {
		return nil, badConn(s.c, err)
	}
	return &sqlStmt{s: s, name: name}, nil
}

func (s *sqlConn) Close() error { return s.c.Close() }

func (s *sqlConn) Begin() (driver.Tx, error) {
	return s.BeginTx(context.Background(), driver.TxOptions{})
}

// BeginTx is BEGIN [ISOLATION LEVEL ...] (the engine's levels: SNAPSHOT, REPEATABLE READ (its snapshot), READ
// COMMITTED, READ UNCOMMITTED (read committed: uncommitted data is never visible) and SERIALIZABLE); a read-only
// transaction is refused (the engine has none).
func (s *sqlConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if s.c.failed() != nil {
		return nil, driver.ErrBadConn
	}
	if opts.ReadOnly {
		return nil, errf(CodeUnsupported, "a read-only transaction (imagedb's BEGIN has no READ ONLY)")
	}
	q := "BEGIN"
	switch sql.IsolationLevel(opts.Isolation) {
	case sql.LevelDefault:
	case sql.LevelReadUncommitted:
		q += " ISOLATION LEVEL READ UNCOMMITTED"
	case sql.LevelReadCommitted:
		q += " ISOLATION LEVEL READ COMMITTED"
	case sql.LevelRepeatableRead:
		q += " ISOLATION LEVEL REPEATABLE READ"
	case sql.LevelSnapshot:
		q += " ISOLATION LEVEL SNAPSHOT"
	case sql.LevelSerializable:
		q += " ISOLATION LEVEL SERIALIZABLE"
	default:
		return nil, errf(CodeUnsupported, "the isolation level %v", sql.IsolationLevel(opts.Isolation))
	}
	if _, err := s.c.Exec(ctx, q); err != nil {
		return nil, badConn(s.c, err)
	}
	return &sqlTx{s: s}, nil
}

func values(args []driver.NamedValue) ([]any, error) {
	out := make([]any, len(args))
	for i, a := range args {
		if a.Name != "" {
			return nil, errf(CodeInvalid, "a named parameter (%s): imagedb's are ordinal, $1, $2, ...", a.Name)
		}
		out[i] = a.Value
	}
	return out, nil
}

func (s *sqlConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if s.c.failed() != nil {
		return nil, driver.ErrBadConn
	}
	vals, err := values(args)
	if err != nil {
		return nil, err
	}
	d, err := s.c.Exec(ctx, query, vals...)
	if err != nil {
		return nil, badConn(s.c, err)
	}
	return result{d}, nil
}

func (s *sqlConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if s.c.failed() != nil {
		return nil, driver.ErrBadConn
	}
	vals, err := values(args)
	if err != nil {
		return nil, err
	}
	r, err := s.c.Query(ctx, query, vals...)
	if err != nil {
		return nil, badConn(s.c, err)
	}
	return &sqlRows{r: r}, nil
}

func (s *sqlConn) Ping(ctx context.Context) error {
	if err := s.c.Ping(ctx); err != nil {
		return driver.ErrBadConn
	}
	return nil
}

func (s *sqlConn) ResetSession(ctx context.Context) error {
	if s.c.failed() != nil {
		return driver.ErrBadConn
	}
	return nil
}

func (s *sqlConn) IsValid() bool { return s.c.failed() == nil }

// CheckNamedValue takes every parameter ToValue takes (typed NULLs, Decimal, UUID, Date, ...), converted here once.
func (s *sqlConn) CheckNamedValue(nv *driver.NamedValue) error {
	if nv.Name != "" {
		return errf(CodeInvalid, "a named parameter (%s): imagedb's are ordinal, $1, $2, ...", nv.Name)
	}
	v, err := ToValue(nv.Value)
	if err != nil {
		return err
	}
	nv.Value = v
	return nil
}

// badConn: a connection found unusable before its request could reach the server is database/sql's ErrBadConn (it
// retries on another); one that failed while the request was under way is the error itself (it may have run).
func badConn(c *Conn, err error) error {
	if errors.Is(err, ErrClosed) {
		return driver.ErrBadConn
	}
	return err
}

type result struct{ d *Done }

func (r result) LastInsertId() (int64, error) {
	return 0, errf(CodeUnsupported, "LastInsertId (use RETURNING)")
}

func (r result) RowsAffected() (int64, error) {
	if r.d.Count > math.MaxInt64 {
		return 0, errf(CodeLimit, "a count past int64")
	}
	return int64(r.d.Count), nil
}

type sqlTx struct{ s *sqlConn }

func (t *sqlTx) Commit() error {
	_, err := t.s.c.Exec(context.Background(), "COMMIT")
	return err
}

func (t *sqlTx) Rollback() error {
	_, err := t.s.c.Exec(context.Background(), "ROLLBACK")
	return err
}

// sqlStmt is a statement prepared on the server by name; Close deallocates it.
type sqlStmt struct {
	s      *sqlConn
	name   string
	closed bool
}

var (
	_ driver.StmtExecContext  = (*sqlStmt)(nil)
	_ driver.StmtQueryContext = (*sqlStmt)(nil)
)

func (st *sqlStmt) Close() error {
	if st.closed || st.s.c.failed() != nil {
		return nil
	}
	st.closed = true
	return st.s.c.Deallocate(context.Background(), st.name)
}

// NumInput is -1: the server's PREPARE does not say how many parameters a statement takes.
func (st *sqlStmt) NumInput() int { return -1 }

func (st *sqlStmt) Exec(args []driver.Value) (driver.Result, error) {
	return st.ExecContext(context.Background(), named(args))
}

func (st *sqlStmt) Query(args []driver.Value) (driver.Rows, error) {
	return st.QueryContext(context.Background(), named(args))
}

func named(args []driver.Value) []driver.NamedValue {
	nv := make([]driver.NamedValue, len(args))
	for i, a := range args {
		nv[i] = driver.NamedValue{Ordinal: i + 1, Value: a}
	}
	return nv
}

func (st *sqlStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	vals, err := values(args)
	if err != nil {
		return nil, err
	}
	res, err := st.s.c.Execute(ctx, st.name, vals)
	if err != nil {
		return nil, badConn(st.s.c, err)
	}
	return result{&res[0].Done}, nil
}

// QueryContext runs the prepared statement; its rows are read whole (an EXECUTE's answer, its sets' results).
func (st *sqlStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	vals, err := values(args)
	if err != nil {
		return nil, err
	}
	res, err := st.s.c.Execute(ctx, st.name, vals)
	if err != nil {
		return nil, badConn(st.s.c, err)
	}
	return &resultRows{res: res[0]}, nil
}

// ---- rows ----

type sqlRows struct{ r *Rows }

var (
	_ driver.RowsColumnTypeScanType         = (*sqlRows)(nil)
	_ driver.RowsColumnTypeDatabaseTypeName = (*sqlRows)(nil)
	_ driver.RowsColumnTypePrecisionScale   = (*sqlRows)(nil)
	_ driver.RowsColumnTypeLength           = (*sqlRows)(nil)
)

func names(cols []Column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Name
	}
	return out
}

func (r *sqlRows) Columns() []string { return names(r.r.cols) }
func (r *sqlRows) Close() error      { return r.r.Close() }

func (r *sqlRows) Next(dest []driver.Value) error {
	if !r.r.Next() {
		if r.r.err != nil {
			return r.r.err
		}
		return io.EOF
	}
	for i := range r.r.cur {
		dest[i] = FromValue(&r.r.cur[i])
	}
	return nil
}

func (r *sqlRows) ColumnTypeScanType(i int) reflect.Type               { return scanType(r.r.cols[i].Type) }
func (r *sqlRows) ColumnTypeDatabaseTypeName(i int) string             { return r.r.cols[i].DatabaseTypeName() }
func (r *sqlRows) ColumnTypePrecisionScale(i int) (int64, int64, bool) { return precScale(r.r.cols[i]) }
func (r *sqlRows) ColumnTypeLength(i int) (int64, bool)                { return length(r.r.cols[i]) }

func precScale(c Column) (int64, int64, bool) {
	if c.Type != TypeDecimal {
		return 0, 0, false
	}
	p := c.Precision
	if p == 0 { // not known: 38 digits
		p = wire.DecimalMax
	}
	return int64(p), int64(c.Scale), true
}

func length(c Column) (int64, bool) {
	switch c.Type {
	case TypeText:
		if c.Precision > 0 {
			return int64(c.Precision), true
		}
		return math.MaxInt64, true
	case TypeBytea:
		return math.MaxInt64, true
	}
	return 0, false
}

// resultRows is a Result already read whole, as driver.Rows.
type resultRows struct {
	res *Result
	at  int
}

func (r *resultRows) Columns() []string { return names(r.res.Columns) }
func (r *resultRows) Close() error      { return nil }

func (r *resultRows) Next(dest []driver.Value) error {
	if r.at >= len(r.res.Rows) {
		return io.EOF
	}
	for i, v := range r.res.Rows[r.at] {
		dest[i] = v
	}
	r.at++
	return nil
}

func (r *resultRows) ColumnTypeScanType(i int) reflect.Type { return scanType(r.res.Columns[i].Type) }
func (r *resultRows) ColumnTypeDatabaseTypeName(i int) string {
	return r.res.Columns[i].DatabaseTypeName()
}
func (r *resultRows) ColumnTypePrecisionScale(i int) (int64, int64, bool) {
	return precScale(r.res.Columns[i])
}
func (r *resultRows) ColumnTypeLength(i int) (int64, bool) { return length(r.res.Columns[i]) }
