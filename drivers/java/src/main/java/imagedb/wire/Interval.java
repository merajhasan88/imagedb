package imagedb.wire;

/** INTERVAL's three fields as the wire carries them (any triple): months, days, microseconds */
public final class Interval {
    public final int months;
    public final int days;
    public final long micros;

    public Interval(int months, int days, long micros) {
        this.months = months;
        this.days = days;
        this.micros = micros;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Interval)) return false;
        Interval x = (Interval) o;
        return months == x.months && days == x.days && micros == x.micros;
    }

    @Override
    public int hashCode() { return (months * 31 + days) * 31 + Long.hashCode(micros); }

    @Override
    public String toString() { return months + " mon " + days + " days " + micros + " us"; }
}
