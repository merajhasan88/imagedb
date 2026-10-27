#!/bin/sh
# throwaway: one command in a measurement window, as bench/whole.sh opens one: the power profile
# (power-profiles-daemon) and the CPU governor set to performance, both put back on exit
#   sh .work/window.sh CMD [ARG...]
set -eu
GOV=/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
old=$(cat "$GOV" 2>/dev/null || echo "")
PP=$(command -v powerprofilesctl || true)
oldpp=$([ -n "$PP" ] && "$PP" get 2>/dev/null || true)
restore() {
    set +e
    [ -n "$old" ] && for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo "$old" > "$g"; done
    [ -n "$oldpp" ] && "$PP" set "$oldpp"
}
trap restore EXIT INT TERM
[ -n "$oldpp" ] && "$PP" set performance
[ -n "$old" ] && for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g"; done
sleep 1
echo "window: profile $([ -n "$PP" ] && "$PP" get), governor $(cat "$GOV"), load $(cut -d' ' -f1 /proc/loadavg)," \
     "mean clock $(awk '/^cpu MHz/ {s += $4; n++} END {if (n) printf "%.0f", s / n}' /proc/cpuinfo) MHz"
"$@"
