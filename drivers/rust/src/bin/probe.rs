//! The coordinator's acceptance probe: `probe SOCKET PASSWORD SQL` logs in over the Unix socket as `admin`, runs the
//! one statement and prints its rows (one line each, values joined by '|', a NULL empty; a statement without rows: its
//! status), exit 0; or prints the driver's error, exit 1.
use imagedb::{Client, Value};

fn text(v: &Value) -> String {
    match v {
        Value::Null(_) => String::new(),
        Value::Int64(x) => x.to_string(),
        Value::Float64(x) => x.to_string(),
        Value::Bool(x) => x.to_string(),
        Value::Text(s) | Value::Enum(s) => s.clone(),
        Value::Decimal(d) => d.to_string(),
        Value::Timestamp(t) => t.to_string(),
        Value::TimestampTz(t) => t.to_string(),
        Value::Date(d) => d.to_string(),
        Value::Time(t) => t.to_string(),
        Value::Uuid(u) => u.to_string(),
        Value::Bytea(b) => format!("\\x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
        Value::Interval(i) => format!("{} mons {} days {} us", i.months, i.days, i.micros),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: probe SOCKET PASSWORD SQL");
        std::process::exit(2);
    }
    let r = Client::connect_unix(&args[1], "admin", &args[2]).and_then(|mut c| c.query(&args[3], &[]));
    match r {
        Ok(res) => {
            if res.columns.is_some() {
                for row in &res.rows {
                    println!("{}", row.values().iter().map(text).collect::<Vec<_>>().join("|"));
                }
            } else {
                println!("{}", res.done.status);
            }
        }
        Err(e) => {
            eprintln!("probe: {e}");
            std::process::exit(1);
        }
    }
}
