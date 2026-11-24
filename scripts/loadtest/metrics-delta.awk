# metrics-delta.awk -- per-cell delta of the node's own Prometheus histograms.
#
# Usage:
#   awk -f scripts/loadtest/metrics-delta.awk before.prom after.prom
#
# The node exposes cumulative histograms (stellereum/src/metrics.rs). A cell
# needs the *difference* between two scrapes taken around one load wave, so
# this program subtracts bucket/sum/count and estimates quantiles by linear
# interpolation inside the bucket that contains the rank. Prometheus itself
# would do the same from prometheus_histogram_quantile(); we cannot assume a
# Prometheus server is running next to a local cluster.
#
# Output: one JSON object on stdout. A family with no observations is `null`.
# A quantile that falls in the `+Inf` bucket is a JSON string such as
# ">=10.000000": the true value is above the last finite bound and the data
# cannot say how far. Callers must not turn that into a number.
#
# Only these families are read; they are the ones the matrix publishes:
#   stell_apply_seconds
#   stell_cpu_per_block_seconds
#   stell_block_interval_seconds
#   stell_block_txs
#
# Exit code is non-zero on a malformed line, a counter reset (after < before)
# or a missing before/after pair.

BEGIN {
    split("apply_seconds cpu_per_block_seconds " \
          "block_interval_seconds block_txs", families, " ")
    for (i in families) wanted[families[i]] = 1
    file_no = 0
}

# Skip comments and empty lines.
/^[[:space:]]*#/ { next }
/^[[:space:]]*$/ { next }

# Histogram bucket: <name>_bucket{le="<bound>"} <cumulative>
/bucket\{le="/ {
    line = $0
    name = line
    sub(/^stell_/, "", name)
    sub(/_bucket\{.*/, "", name)
    if (!(name in wanted)) { next }
    rest = line
    sub(/^[^{]*\{le="/, "", rest)
    le = rest
    sub(/".*/, "", le)
    value = rest
    sub(/^[^"]*"\}[[:space:]]*/, "", value)
    if (value !~ /^[0-9.eE+-]+$/) {
        printf("metrics-delta: bad bucket value for %s le=%s: %s\n", name, le, value) > "/dev/stderr"
        bad = 1
        next
    }
    if (FILENAME == ARGV[1]) {
        before[name, le] = value + 0
        if (!((name, le) in before_le)) {
            before_le[name, le] = ++before_n[name]
            before_order[name, before_n[name]] = le
        }
    } else {
        after[name, le] = value + 0
        if (!((name, le) in after_le)) {
            after_le[name, le] = ++after_n[name]
            after_order[name, after_n[name]] = le
        }
    }
    next
}

# Histogram sum: <name>_sum <value>
/_sum([[:space:]]|$)/ {
    line = $0
    name = line
    sub(/^stell_/, "", name)
    sub(/_sum.*/, "", name)
    if (!(name in wanted)) { next }
    value = line
    sub(/^[^[:space:]]+[[:space:]]*/, "", value)
    if (value !~ /^[0-9.eE+-]+$/) { next }
    if (FILENAME == ARGV[1]) { before_sum[name] = value + 0 }
    else { after_sum[name] = value + 0 }
    next
}

# Histogram count: <name>_count <value>
/_count([[:space:]]|$)/ {
    line = $0
    name = line
    sub(/^stell_/, "", name)
    sub(/_count.*/, "", name)
    if (!(name in wanted)) { next }
    value = line
    sub(/^[^[:space:]]+[[:space:]]*/, "", value)
    if (value !~ /^[0-9.eE+-]+$/) { next }
    if (FILENAME == ARGV[1]) { before_count[name] = value + 0 }
    else { after_count[name] = value + 0 }
    next
}

END {
    if (bad) { exit 2 }
    if (after_n["apply_seconds"] + after_n["cpu_per_block_seconds"] + \
        after_n["block_interval_seconds"] + after_n["block_txs"] == 0) {
        print "{\"error\":\"no matrix histograms in the after scrape\"}"
        exit 3
    }
    printf("{")
    printf("\"apply\":%s,", family_json("apply_seconds"))
    printf("\"cpu_per_block\":%s,", family_json("cpu_per_block_seconds"))
    printf("\"block_interval\":%s,", family_json("block_interval_seconds"))
    printf("\"block_txs\":%s", family_json("block_txs"))
    printf("}\n")
    if (reset) { exit 4 }
}

function family_json(name,    n, i, total, ssum, mean, d, le, q50, q95, q99) {
    if (!(name in after_count) || !(name in before_count)) { return "null" }
    n = after_count[name] - before_count[name]
    if (n < 0) { reset = 1; return "null" }
    if (n == 0) { return "null" }
    ssum = (name in after_sum && name in before_sum) ? after_sum[name] - before_sum[name] : 0
    if (ssum < 0 || !(ssum == ssum)) { reset = 1; return "null" }
    mean = ssum / n
    # A bucket present only in the after scrape was pre-seeded at zero in the
    # before scrape; treat it that way rather than skipping it.
    for (i = 1; i <= after_n[name]; i++) {
        le = after_order[name, i]
        d = after[name, le] - ((name, le) in before ? before[name, le] : 0)
        if (d < 0) { reset = 1; return "null" }
    }
    q50 = quantile(name, 0.50)
    q95 = quantile(name, 0.95)
    q99 = quantile(name, 0.99)
    return sprintf("{\"n\":%d,\"p50\":%s,\"p95\":%s,\"p99\":%s,\"mean\":%.9f}",
                   n, json_value(q50), json_value(q95), json_value(q99), mean)
}

# Linear interpolation inside the containing bucket. `prev_le` starts at 0 for
# every family because every ship histogram has a non-negative domain.
function quantile(name, q,    i, le, hi, target, cum, prev_cum, prev_le, inb, total) {
    total = after_count[name] - before_count[name]
    if (total <= 0) { return "" }
    target = q * total
    cum = 0
    prev_cum = 0
    prev_le = 0
    for (i = 1; i <= after_n[name]; i++) {
        le = after_order[name, i]
        cum = after[name, le] - ((name, le) in before ? before[name, le] : 0)
        if (cum + 0 < prev_cum) { return "" }
        if (cum >= target) {
            if (le == "+Inf" || le == "Inf") {
                return ">=" sprintf("%.6f", prev_le)
            }
            hi = le + 0
            inb = cum - prev_cum
            if (inb <= 0) { return sprintf("%.6f", hi) }
            return sprintf("%.6f", prev_le + (hi - prev_le) * (target - prev_cum) / inb)
        }
        prev_cum = cum
        if (le != "+Inf" && le != "Inf") { prev_le = le + 0 }
    }
    return ">=" sprintf("%.6f", prev_le)
}

function json_value(v) {
    if (v == "") { return "null" }
    if (v ~ /^>=/) { return "\"" v "\"" }
    return v
}
