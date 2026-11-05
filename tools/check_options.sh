#!/bin/sh
# make lint (P1 A1): each session setting (SET name), command-line option and environment variable that src/ reads is
# named in README.md's "## Options and settings" section, as `name` followed by a backtick, a space or an =, so the
# reference cannot fall behind the code. POSIX sh and awk.
set -eu
cd "$(dirname "$0")/.."
{
    grep -oh 'strcmp(st->set_name, "[a-z_]*")' src/sql_exec.c | sed 's/.*"\(.*\)".*/\1/'
    grep -oh '"--[a-z][a-z-]*"' src/main.c | tr -d '"'
    grep -oh 'getenv("IMDB_[A-Z0-9_]*")' src/*.c | sed 's/.*"\(.*\)".*/\1/'
} | sort -u | awk -v readme=README.md '
BEGIN {
    while ((getline l < readme) > 0) {
        if (l == "## Options and settings") { on = 1; continue }
        if (on && l ~ /^## /) break
        if (on) sec = sec l "\n"
    }
    if (sec == "") { print "README.md: no \"## Options and settings\" section"; bad = 1; exit }
}
{
    q = "`" $0
    if (!index(sec, q "`") && !index(sec, q " ") && !index(sec, q "=")) {
        print "README.md: \"## Options and settings\" lacks `" $0 "`"
        bad = 1
    }
    n++
}
END { if (!bad && n < 40) { print "check_options.sh: only " n " names found in src/: the patterns no longer match"; bad = 1 }; exit bad }'
