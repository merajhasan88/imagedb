# Collects "NAME = hex" fields whose hex may continue on following indented lines (RFC test-vector layout); the "="
# may be missing (RFC 4231's test case 3). Page breaks (form feeds, page footers and headers) are skipped.
# Usage: awk -v names="Key|Data|HMAC-SHA-256" -v start=N -v end=M -f fields.awk file
# Prints "NAME<TAB>hex<TAB>line" once per field (hex lowercased, spaces and 0x removed).
function flush() { if (cur != "") { printf "%s\t%s\t%d\n", cur, tolower(val), at; cur = "" } }
NR < start || NR > end { next }
/^\f *$/ || /\[Page [0-9]+\] *$/ || /^RFC [0-9]+  / { next }
{
  line = $0
  if (match(line, "^ *(" names ")( *=| +)")) {
    flush()
    name = substr(line, RSTART, RLENGTH); sub(/ *=? *$/, "", name); gsub(/^ +| +$/, "", name)
    rest = substr(line, RSTART + RLENGTH); sub(/^ +/, "", rest); sub(/^0x/, "", rest)
    split(rest, t, " "); cur = name; val = t[1]; at = NR
    next
  }
  if (cur != "" && line ~ /^ +[0-9a-fA-F]+( |$)/ && line !~ /=/) {
    s = line; sub(/^ +/, "", s); split(s, t, " "); val = val t[1]; next
  }
  flush()
}
END { flush() }
