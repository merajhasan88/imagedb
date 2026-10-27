# throwaway (2026-10-26, open item A): ATA command latency from `perf script -F comm,pid,time,event,trace` of
# libata:ata_qc_issue and libata:ata_qc_complete_done, paired by port and tag. Prints one line per command,
# "L cmd seconds issue_time", for sort; .work/ata-summary.sh makes the distribution and the slow list.
#   awk -f .work/ata-latency.awk perf.txt
function field(name,    j) { for (j = i + 1; j <= NF; j++) if (index($j, name "=") == 1) return substr($j, length(name) + 2); return "" }
{
    for (i = 1; i <= NF; i++) if ($i == "libata:ata_qc_issue:" || $i == "libata:ata_qc_complete_done:") break
    if (i > NF) next
    t = $(i - 1); sub(/:$/, "", t); t += 0
    k = field("ata_port") ":" field("tag")
    if ($i == "libata:ata_qc_issue:") { it[k] = t; ic[k] = field("cmd"); next }
    if (!(k in it)) next
    printf "L %s %.6f %.6f\n", ic[k], t - it[k], it[k]
    delete it[k]
}
