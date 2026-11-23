//! Native values for IMDBWIR1's types (docs/n1-design.md §4, "Values"): each wire type to a Rust type without loss.

use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// A value's wire type (§4: tags 1 to 13; 0 is a NULL's of no type, or a column whose type the statement does not know).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Type {
    None = 0,
    Int64 = 1,
    Float64 = 2,
    Bool = 3,
    Text = 4,
    Decimal = 5,
    Timestamp = 6,
    TimestampTz = 7,
    Date = 8,
    Time = 9,
    Uuid = 10,
    Bytea = 11,
    Interval = 12,
    Enum = 13,
}

impl Type {
    pub fn from_u8(t: u8) -> Option<Type> {
        Some(match t {
            0 => Type::None,
            1 => Type::Int64,
            2 => Type::Float64,
            3 => Type::Bool,
            4 => Type::Text,
            5 => Type::Decimal,
            6 => Type::Timestamp,
            7 => Type::TimestampTz,
            8 => Type::Date,
            9 => Type::Time,
            10 => Type::Uuid,
            11 => Type::Bytea,
            12 => Type::Interval,
            13 => Type::Enum,
            _ => return None,
        })
    }
}

const POW10: [u64; 20] = {
    let mut t = [1u64; 20];
    let mut i = 1;
    while i < 20 {
        t[i] = t[i - 1] * 10;
        i += 1;
    }
    t
};

/// 10^k for k in 0..=38, exactly.
pub fn pow10_i128(k: u32) -> i128 {
    assert!(k <= 38);
    if k <= 19 { POW10[k as usize] as i128 } else { POW10[(k - 19) as usize] as i128 * POW10[19] as i128 }
}

/// A DECIMAL: an unscaled i128 below 10^38 in magnitude and a scale of 0 to 38 (§4: one form for every column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Decimal {
    unscaled: i128,
    scale: u8,
}

impl Decimal {
    /// The largest unscaled magnitude: 10^38 - 1.
    pub const MAX_UNSCALED: i128 = 99_999_999_999_999_999_999_999_999_999_999_999_999;

    pub fn new(unscaled: i128, scale: u8) -> Result<Decimal, Error> {
        if scale > 38 || unscaled > Self::MAX_UNSCALED || unscaled < -Self::MAX_UNSCALED {
            return Err(Error::Invalid("a DECIMAL is at most 38 digits at a scale of 0 to 38".into()));
        }
        Ok(Decimal { unscaled, scale })
    }

    pub fn unscaled(&self) -> i128 {
        self.unscaled
    }

    pub fn scale(&self) -> u8 {
        self.scale
    }

    /// The digits of the unscaled value (at least 1).
    pub fn digits(&self) -> u32 {
        let mut m = self.unscaled.unsigned_abs();
        let mut n = 1;
        while m >= 10 {
            m /= 10;
            n += 1;
        }
        n
    }
}

impl From<i64> for Decimal {
    fn from(v: i64) -> Self {
        Decimal { unscaled: v as i128, scale: 0 }
    }
}

impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.unscaled.unsigned_abs();
        let digits = m.to_string();
        let s = self.scale as usize;
        let sign = if self.unscaled < 0 { "-" } else { "" };
        if s == 0 {
            return write!(f, "{sign}{digits}");
        }
        let padded = if digits.len() <= s { format!("{}{}", "0".repeat(s + 1 - digits.len()), digits) } else { digits };
        let (ip, fp) = padded.split_at(padded.len() - s);
        write!(f, "{sign}{ip}.{fp}")
    }
}

impl FromStr for Decimal {
    type Err = Error;
    /// `[+-]digits[.digits]`: exact, its scale the digits after the point (never rounded).
    fn from_str(s: &str) -> Result<Decimal, Error> {
        let bad = || Error::Invalid(format!("not a decimal of at most 38 digits: {s:?}"));
        let (neg, body) = match s.as_bytes().first() {
            Some(b'-') => (true, &s[1..]),
            Some(b'+') => (false, &s[1..]),
            _ => (false, s),
        };
        let (ip, fp) = match body.find('.') {
            Some(i) => (&body[..i], &body[i + 1..]),
            None => (body, ""),
        };
        if (ip.is_empty() && fp.is_empty()) || !ip.bytes().chain(fp.bytes()).all(|c| c.is_ascii_digit()) {
            return Err(bad());
        }
        if fp.len() > 38 {
            return Err(bad());
        }
        let mut v: i128 = 0;
        for c in ip.bytes().chain(fp.bytes()) {
            v = v.checked_mul(10).and_then(|x| x.checked_add((c - b'0') as i128)).ok_or_else(bad)?;
            if v > Decimal::MAX_UNSCALED {
                return Err(bad());
            }
        }
        Decimal::new(if neg { -v } else { v }, fp.len() as u8).map_err(|_| bad())
    }
}

// ---- the calendar: proleptic Gregorian, days since 1970-01-01 (H. Hinnant's days_from_civil and civil_from_days) ----

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                29
            } else {
                28
            }
        }
    }
}

/// A DATE: days since 1970-01-01, 0001-01-01 to 9999-12-31.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date(i32);

impl Date {
    pub const MIN_DAYS: i32 = -719162; // 0001-01-01
    pub const MAX_DAYS: i32 = 2932896; // 9999-12-31

    pub fn from_days(days: i32) -> Result<Date, Error> {
        if !(Self::MIN_DAYS..=Self::MAX_DAYS).contains(&days) {
            return Err(Error::Invalid("a DATE is 0001-01-01 to 9999-12-31".into()));
        }
        Ok(Date(days))
    }

    pub fn from_ymd(y: i32, m: u32, d: u32) -> Result<Date, Error> {
        if !(1..=9999).contains(&y) || !(1..=12).contains(&m) || d < 1 || d > days_in_month(y as i64, m) {
            return Err(Error::Invalid("a DATE is a day of 0001-01-01 to 9999-12-31".into()));
        }
        Date::from_days(days_from_civil(y as i64, m, d) as i32)
    }

    pub fn days(&self) -> i32 {
        self.0
    }

    pub fn ymd(&self) -> (i32, u32, u32) {
        let (y, m, d) = civil_from_days(self.0 as i64);
        (y as i32, m, d)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, m, d) = self.ymd();
        write!(f, "{y:04}-{m:02}-{d:02}")
    }
}

const US_PER_DAY: i64 = 86_400_000_000;

/// A TIME: microseconds since midnight, 0 to 86,399,999,999.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(i64);

impl Time {
    pub const MAX_MICROS: i64 = US_PER_DAY - 1;

    pub fn from_micros(us: i64) -> Result<Time, Error> {
        if !(0..=Self::MAX_MICROS).contains(&us) {
            return Err(Error::Invalid("a TIME is 00:00:00 to 23:59:59.999999".into()));
        }
        Ok(Time(us))
    }

    pub fn from_hms_micro(h: u32, m: u32, s: u32, us: u32) -> Result<Time, Error> {
        if h > 23 || m > 59 || s > 59 || us > 999_999 {
            return Err(Error::Invalid("a TIME's fields".into()));
        }
        Time::from_micros(((h as i64 * 60 + m as i64) * 60 + s as i64) * 1_000_000 + us as i64)
    }

    pub fn micros(&self) -> i64 {
        self.0
    }

    /// Hours, minutes, seconds and microseconds.
    pub fn hms_micro(&self) -> (u32, u32, u32, u32) {
        let us = (self.0 % 1_000_000) as u32;
        let s = self.0 / 1_000_000;
        ((s / 3600) as u32, (s / 60 % 60) as u32, (s % 60) as u32, us)
    }
}

fn write_hms(f: &mut fmt::Formatter<'_>, (h, m, s, us): (u32, u32, u32, u32)) -> fmt::Result {
    write!(f, "{h:02}:{m:02}:{s:02}")?;
    if us != 0 {
        let mut frac = format!("{us:06}");
        while frac.ends_with('0') {
            frac.pop();
        }
        write!(f, ".{frac}")?;
    }
    Ok(())
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hms(f, self.hms_micro())
    }
}

const TS_MIN: i64 = -62_135_596_800_000_000; // 0001-01-01 00:00:00
const TS_MAX: i64 = 253_402_300_799_999_999; // 9999-12-31 23:59:59.999999

fn ts_parts(us: i64) -> (Date, Time) {
    let days = us.div_euclid(US_PER_DAY);
    let tod = us.rem_euclid(US_PER_DAY);
    (Date(days as i32), Time(tod))
}

/// A TIMESTAMP (no zone): microseconds since 1970-01-01 00:00 on the civil calendar, years 1 to 9999.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

/// A TIMESTAMPTZ: an instant, microseconds since the Unix epoch (UTC), years 1 to 9999. A session's zone is for text
/// alone: the wire carries the instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimestampTz(i64);

macro_rules! ts_common {
    ($t:ident, $what:literal) => {
        impl $t {
            pub const MIN_MICROS: i64 = TS_MIN;
            pub const MAX_MICROS: i64 = TS_MAX;

            pub fn from_micros(us: i64) -> Result<$t, Error> {
                if !(TS_MIN..=TS_MAX).contains(&us) {
                    return Err(Error::Invalid(concat!("a ", $what, " is in years 1 to 9999").into()));
                }
                Ok($t(us))
            }

            pub fn from_parts(date: Date, time: Time) -> $t {
                $t(date.0 as i64 * US_PER_DAY + time.0)
            }

            pub fn micros(&self) -> i64 {
                self.0
            }

            pub fn date(&self) -> Date {
                ts_parts(self.0).0
            }

            pub fn time(&self) -> Time {
                ts_parts(self.0).1
            }
        }
    };
}
ts_common!(Timestamp, "TIMESTAMP");
ts_common!(TimestampTz, "TIMESTAMPTZ");

impl TimestampTz {
    /// The instant as std's SystemTime.
    pub fn to_system_time(&self) -> std::time::SystemTime {
        let d = std::time::Duration::from_micros(self.0.unsigned_abs());
        if self.0 >= 0 { std::time::UNIX_EPOCH + d } else { std::time::UNIX_EPOCH - d }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (d, t) = ts_parts(self.0);
        write!(f, "{d} ")?;
        write_hms(f, t.hms_micro())
    }
}

impl fmt::Display for TimestampTz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (d, t) = ts_parts(self.0);
        write!(f, "{d} ")?;
        write_hms(f, t.hms_micro())?;
        write!(f, "+00")
    }
}

/// An INTERVAL: months, days and microseconds, each its own field (§4: any triple; SQL's order is the engine's).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Interval {
    pub months: i32,
    pub days: i32,
    pub micros: i64,
}

impl Interval {
    pub fn new(months: i32, days: i32, micros: i64) -> Interval {
        Interval { months, days, micros }
    }
}

/// A UUID's 16 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid(pub [u8; 16]);

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i == 4 || i == 6 || i == 8 || i == 10 {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Uuid {
    type Err = Error;
    /// The canonical 8-4-4-4-12 form, either case.
    fn from_str(s: &str) -> Result<Uuid, Error> {
        let b = s.as_bytes();
        let bad = || Error::Invalid("a UUID is 8-4-4-4-12 hexadecimal digits".into());
        if b.len() != 36 {
            return Err(bad());
        }
        let mut out = [0u8; 16];
        let mut k = 0;
        let mut i = 0;
        while i < 36 {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                if b[i] != b'-' {
                    return Err(bad());
                }
                i += 1;
                continue;
            }
            let hi = (b[i] as char).to_digit(16).ok_or_else(bad)?;
            let lo = (b[i + 1] as char).to_digit(16).ok_or_else(bad)?;
            out[k] = (hi * 16 + lo) as u8;
            k += 1;
            i += 2;
        }
        Ok(Uuid(out))
    }
}

/// A value on the wire: a typed NULL, or one of the 13 types. FLOAT64 is its bits (finite, never -0: the engine keeps one
/// zero); a NULL keeps a type, which the engine binds a NULL parameter by (`Null(Type::None)` is a NULL of no type).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null(Type),
    Int64(i64),
    Float64(f64),
    Bool(bool),
    Text(String),
    Decimal(Decimal),
    Timestamp(Timestamp),
    TimestampTz(TimestampTz),
    Date(Date),
    Time(Time),
    Uuid(Uuid),
    Bytea(Vec<u8>),
    Interval(Interval),
    /// An ENUM's label, as a result's value. A parameter is never a non-NULL ENUM: a label is sent as TEXT (§4).
    Enum(String),
}

impl Value {
    pub fn ty(&self) -> Type {
        match self {
            Value::Null(t) => *t,
            Value::Int64(_) => Type::Int64,
            Value::Float64(_) => Type::Float64,
            Value::Bool(_) => Type::Bool,
            Value::Text(_) => Type::Text,
            Value::Decimal(_) => Type::Decimal,
            Value::Timestamp(_) => Type::Timestamp,
            Value::TimestampTz(_) => Type::TimestampTz,
            Value::Date(_) => Type::Date,
            Value::Time(_) => Type::Time,
            Value::Uuid(_) => Type::Uuid,
            Value::Bytea(_) => Type::Bytea,
            Value::Interval(_) => Type::Interval,
            Value::Enum(_) => Type::Enum,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null(_))
    }
}

/// A Rust type's wire type: what a `None` of it is sent as (a NULL keeps its type).
pub trait SqlType {
    const TYPE: Type;
}

macro_rules! into_value {
    ($t:ty, $ty:expr, |$v:ident| $e:expr) => {
        impl From<$t> for Value {
            fn from($v: $t) -> Value {
                $e
            }
        }
        impl SqlType for $t {
            const TYPE: Type = $ty;
        }
    };
}
into_value!(i64, Type::Int64, |v| Value::Int64(v));
into_value!(i32, Type::Int64, |v| Value::Int64(v as i64));
into_value!(i16, Type::Int64, |v| Value::Int64(v as i64));
into_value!(f64, Type::Float64, |v| Value::Float64(v));
into_value!(bool, Type::Bool, |v| Value::Bool(v));
into_value!(String, Type::Text, |v| Value::Text(v));
into_value!(&str, Type::Text, |v| Value::Text(v.to_string()));
into_value!(Decimal, Type::Decimal, |v| Value::Decimal(v));
into_value!(Timestamp, Type::Timestamp, |v| Value::Timestamp(v));
into_value!(TimestampTz, Type::TimestampTz, |v| Value::TimestampTz(v));
into_value!(Date, Type::Date, |v| Value::Date(v));
into_value!(Time, Type::Time, |v| Value::Time(v));
into_value!(Uuid, Type::Uuid, |v| Value::Uuid(v));
into_value!(Vec<u8>, Type::Bytea, |v| Value::Bytea(v));
into_value!(&[u8], Type::Bytea, |v| Value::Bytea(v.to_vec()));
into_value!(Interval, Type::Interval, |v| Value::Interval(v));

impl<T: Into<Value> + SqlType> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Value {
        match v {
            Some(x) => x.into(),
            None => Value::Null(T::TYPE),
        }
    }
}

/// A value read out of a result as a Rust type: exact or refused (a NULL only into an Option).
pub trait FromValue: Sized {
    fn from_value(v: &Value) -> Result<Self, Error>;
}

fn mismatch(v: &Value, want: &str) -> Error {
    if v.is_null() {
        Error::Invalid(format!("a NULL read as {want} (read it as an Option)"))
    } else {
        Error::Invalid(format!("a {:?} read as {want}", v.ty()))
    }
}

macro_rules! from_value {
    ($t:ty, $want:literal, $($pat:pat => $e:expr),+) => {
        impl FromValue for $t {
            fn from_value(v: &Value) -> Result<$t, Error> {
                match v {
                    $($pat => Ok($e),)+
                    _ => Err(mismatch(v, $want)),
                }
            }
        }
    };
}
from_value!(i64, "i64", Value::Int64(x) => *x);
from_value!(f64, "f64", Value::Float64(x) => *x);
from_value!(bool, "bool", Value::Bool(x) => *x);
from_value!(String, "String", Value::Text(x) => x.clone(), Value::Enum(x) => x.clone());
from_value!(Decimal, "Decimal", Value::Decimal(x) => *x);
from_value!(Timestamp, "Timestamp", Value::Timestamp(x) => *x);
from_value!(TimestampTz, "TimestampTz", Value::TimestampTz(x) => *x);
from_value!(Date, "Date", Value::Date(x) => *x);
from_value!(Time, "Time", Value::Time(x) => *x);
from_value!(Uuid, "Uuid", Value::Uuid(x) => *x);
from_value!(Vec<u8>, "Vec<u8>", Value::Bytea(x) => x.clone());
from_value!(Interval, "Interval", Value::Interval(x) => *x);
impl FromValue for Value {
    fn from_value(v: &Value) -> Result<Value, Error> {
        Ok(v.clone())
    }
}

impl<T: FromValue> FromValue for Option<T> {
    fn from_value(v: &Value) -> Result<Option<T>, Error> {
        if v.is_null() { Ok(None) } else { T::from_value(v).map(Some) }
    }
}
