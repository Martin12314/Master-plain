import json
import math
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


def load_ndjson(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[warn] skipping bad json line {line_no}: {e}", file=sys.stderr)
    return rows


def numeric_values(values):
    return [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]


def pct(values, p):
    vals = sorted(numeric_values(values))
    if not vals:
        return None
    if len(vals) == 1:
        return vals[0]
    k = (len(vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return vals[int(k)]
    d0 = vals[f] * (c - k)
    d1 = vals[c] * (k - f)
    return d0 + d1


def mean(values):
    vals = numeric_values(values)
    return statistics.fmean(vals) if vals else None


def stddev(values):
    vals = numeric_values(values)
    if len(vals) < 2:
        return 0.0 if vals else None
    return statistics.stdev(vals)


def fmt_num(v, unit=""):
    if v is None:
        return "-"
    if unit == "B":
        return f"{v:,.2f} B"
    if unit == "ms":
        return f"{v:.3f} ms"
    if unit == "%":
        return f"{v:.2f}%"
    return f"{v:.3f}"


def pad_order_key(v):
    try:
        return int(v)
    except Exception:
        return 10**9


def first_numeric(row, *names):
    for n in names:
        v = row.get(n)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return v
    return None


def summarize_rows(rows, metric_specs):
    out = []
    for label, field, unit in metric_specs:
        vals = [r.get(field) for r in rows if isinstance(r.get(field), (int, float)) and not isinstance(r.get(field), bool)]
        if not vals:
            continue
        out.append((label, mean(vals), stddev(vals), pct(vals, 95), unit))
    return out


def print_metric_table(title, sections):
    print()
    print(title)
    print("| Metric | Mean | Std. dev. | n95 |")
    print("|---|---:|---:|---:|")
    for section_name, rows in sections:
        if section_name:
            print(f"| **{section_name}** |  |  |  |")
        for label, m, sd, p95, unit in rows:
            print(f"| {label} | {fmt_num(m, unit)} | {fmt_num(sd, unit)} | {fmt_num(p95, unit)} |")


def print_compare_table(title, rows):
    print()
    print(title)
    print("| Metric | Baseline | Proposed | Δ | Δ (%) |")
    print("|---|---:|---:|---:|---:|")
    for label, base_v, prop_v, unit in rows:
        if base_v is None or prop_v is None:
            continue

        delta = prop_v - base_v
        delta_pct = (delta / base_v * 100.0) if base_v != 0 else None

        if unit == "B":
            base_s = f"{base_v:,.2f} B"
            prop_s = f"{prop_v:,.2f} B"
            delta_s = f"{delta:+,.2f} B"
        elif unit == "ms":
            base_s = f"{base_v:.3f} ms"
            prop_s = f"{prop_v:.3f} ms"
            delta_s = f"{delta:+.3f} ms"
        else:
            base_s = f"{base_v:.3f}"
            prop_s = f"{prop_v:.3f}"
            delta_s = f"{delta:+.3f}"

        pct_s = "-" if delta_pct is None else f"{delta_pct:+.2f}%"
        print(f"| {label} | {base_s} | {prop_s} | {delta_s} | {pct_s} |")


def merge_login_iterations(rows):
    """
    Merge protected or baseline login-related events per (runTag, iter).
    Keeps both page-side and SW-side metrics in one record.
    """
    merged = {}

    for r in rows:
        event = r.get("event")
        run_tag = r.get("runTag")
        iter_v = r.get("iter")
        if run_tag is None or iter_v is None:
            continue

        key = (run_tag, int(iter_v))
        rec = merged.setdefault(key, {"runTag": run_tag, "iter": int(iter_v)})

        if event == "protected_login_request":
            rec["kind"] = "protected-login"
            rec["pad_bytes"] = int(r.get("pad_bytes", 0))
            rec["login_fetch_ms"] = first_numeric(r, "login_fetch_ms")
            rec["jwe_encrypt_ms"] = first_numeric(r, "jwe_encrypt_ms")
            rec["login_req_body_bytes"] = first_numeric(r, "login_req_body_bytes")
            rec["login_resp_body_bytes"] = first_numeric(r, "login_resp_body_bytes")
            rec["host_req_header_bytes"] = first_numeric(r, "host_req_header_bytes")
            rec["host_req_body_bytes"] = first_numeric(r, "host_req_body_bytes")
            rec["host_req_sign_header_bytes"] = first_numeric(r, "host_req_sign_header_bytes")
            rec["host_decrypt_ms"] = first_numeric(r, "host_decrypt_ms")
            rec["host_req_verify_ms"] = first_numeric(r, "host_req_verify_ms")
            rec["http_status"] = r.get("http_status")
            rec["ok"] = r.get("ok")

        elif event == "baseline_login_request":
            rec["kind"] = "baseline-login"
            rec["pad_bytes"] = int(r.get("pad_bytes", 0))
            rec["login_fetch_ms"] = first_numeric(r, "login_fetch_ms")
            rec["login_req_body_bytes"] = first_numeric(r, "login_req_body_bytes")
            rec["login_resp_body_bytes"] = first_numeric(r, "login_resp_body_bytes")
            rec["host_req_header_bytes"] = first_numeric(r, "host_req_header_bytes")
            rec["host_req_body_bytes"] = first_numeric(r, "host_req_body_bytes")
            rec["http_status"] = r.get("http_status")
            rec["ok"] = r.get("ok")

        elif event == "sw_fetch_verify":
            bench_kind = r.get("bench_kind")
            if bench_kind == "protected-login":
                rec["kind"] = "protected-login"
                rec["sw_upstream_fetch_ms"] = first_numeric(r, "sw_upstream_fetch_ms")
                rec["sw_digest_verify_ms"] = first_numeric(r, "sw_digest_verify_ms")
                rec["sw_signature_verify_ms"] = first_numeric(r, "sw_signature_verify_ms")
                rec["sw_verify_ms"] = first_numeric(r, "sw_verify_ms")
                rec["sw_total_ms"] = first_numeric(r, "sw_total_ms")
                rec["sw_req_sign_digest_ms"] = first_numeric(r, "sw_req_sign_digest_ms")
                rec["sw_req_sign_signature_ms"] = first_numeric(r, "sw_req_sign_signature_ms")
                rec["sw_req_sign_ms"] = first_numeric(r, "sw_req_sign_ms")
                rec["sw_req_sign_header_bytes"] = first_numeric(r, "sw_req_sign_header_bytes")
                rec["resp_header_bytes"] = first_numeric(r, "resp_header_bytes")
                rec["resp_body_bytes"] = first_numeric(r, "resp_body_bytes")
                rec["resp_total_bytes"] = first_numeric(r, "resp_total_bytes")
                rec["sign_ms"] = first_numeric(r, "sign_ms")
                rec["decrypt_ms"] = first_numeric(r, "decrypt_ms")
                rec["req_verify_ms_resp"] = first_numeric(r, "req_verify_ms")

        elif event == "sw_bypass_fetch":
            rec["bench_kind"] = r.get("bench_kind")
            rec["sw_bypass_fetch_ms"] = first_numeric(r, "sw_bypass_fetch_ms")
            rec["sw_total_ms"] = first_numeric(r, "sw_total_ms")
            rec["resp_header_bytes"] = first_numeric(r, "resp_header_bytes")
            rec["resp_body_bytes"] = first_numeric(r, "resp_body_bytes")
            rec["resp_total_bytes"] = first_numeric(r, "resp_total_bytes")

    return list(merged.values())


def is_baseline_big_row(r):
    if r.get("event") != "sw_bypass_fetch":
        return False

    path = r.get("path") or ""
    run_tag = r.get("runTag") or ""
    mode = r.get("bench_kind") == "big-baseline" or "baseline-big-" in run_tag

    if not mode:
        return False

    return (
        path == "/big.html"
        or path.startswith("/unsigned/")
    )


def is_protected_big_row(r):
    if r.get("event") != "sw_fetch_verify":
        return False
    if r.get("bench_kind") != "big-protected":
        return False
    path = r.get("path") or ""
    return (
        path == "/big.html"
        or path.startswith("/big-assets/")
    )


def collect_big_bundle_stats(rows, mode):
    """
    Groups per (runTag, iter), then sums bundle totals per page-load.
    baseline:
      includes /big.html and /unsigned/*
      uses sw_bypass_fetch + sw_bypass_fetch_ms
    protected:
      includes /big.html and /big-assets/*
      uses sw_fetch_verify + sw_upstream_fetch_ms / sw_verify_ms / sign_ms / sw_total_ms
    """
    groups = defaultdict(list)

    for r in rows:
        run_tag = r.get("runTag")
        iter_v = r.get("iter")
        if run_tag is None or iter_v is None:
            continue

        if mode == "baseline":
            if not is_baseline_big_row(r):
                continue
        else:
            if not is_protected_big_row(r):
                continue

        groups[(run_tag, int(iter_v))].append(r)

    bundle_rows = []
    for _, items in groups.items():
        rec = {}

        rec["bundle_total_bytes"] = sum(first_numeric(x, "resp_total_bytes") or 0 for x in items)
        rec["bundle_header_bytes"] = sum(first_numeric(x, "resp_header_bytes") or 0 for x in items)
        rec["bundle_body_bytes"] = sum(first_numeric(x, "resp_body_bytes") or 0 for x in items)

        if mode == "baseline":
            rec["bundle_fetch_ms"] = sum(first_numeric(x, "sw_bypass_fetch_ms") or 0 for x in items)
            rec["bundle_sw_total_ms"] = sum(first_numeric(x, "sw_total_ms") or 0 for x in items)
            rec["bundle_sign_ms"] = 0
            rec["bundle_sw_verify_ms"] = 0
            rec["bundle_sw_req_sign_ms"] = 0
            rec["bundle_sw_req_sign_header_bytes"] = 0
        else:
            rec["bundle_fetch_ms"] = sum(first_numeric(x, "sw_upstream_fetch_ms") or 0 for x in items)
            rec["bundle_sw_total_ms"] = sum(first_numeric(x, "sw_total_ms") or 0 for x in items)
            rec["bundle_sign_ms"] = sum(first_numeric(x, "sign_ms") or 0 for x in items)
            rec["bundle_sw_verify_ms"] = sum(first_numeric(x, "sw_verify_ms") or 0 for x in items)
            rec["bundle_sw_req_sign_ms"] = sum(first_numeric(x, "sw_req_sign_ms") or 0 for x in items)
            rec["bundle_sw_req_sign_header_bytes"] = sum(first_numeric(x, "sw_req_sign_header_bytes") or 0 for x in items)

        bundle_rows.append(rec)

    return bundle_rows


def collect_login_fetch_values(rows_by_pad):
    out = {}
    for pad, rows in rows_by_pad.items():
        vals = [r.get("login_fetch_ms") for r in rows if isinstance(r.get("login_fetch_ms"), (int, float)) and not isinstance(r.get("login_fetch_ms"), bool)]
        if vals:
            out[pad] = vals
    return out


def make_login_fetch_boxplots(baseline_by_pad, protected_by_pad, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)

    shared_pads = sorted(set(baseline_by_pad) & set(protected_by_pad), key=pad_order_key)
    if not shared_pads:
        print("[warn] no shared baseline/protected pad sizes for box plots", file=sys.stderr)
        return

    # One combined box plot
    data = []
    labels = []
    for pad in shared_pads:
        bvals = [r.get("login_fetch_ms") for r in baseline_by_pad[pad] if isinstance(r.get("login_fetch_ms"), (int, float)) and not isinstance(r.get("login_fetch_ms"), bool)]
        pvals = [r.get("login_fetch_ms") for r in protected_by_pad[pad] if isinstance(r.get("login_fetch_ms"), (int, float)) and not isinstance(r.get("login_fetch_ms"), bool)]
        if bvals:
            data.append(bvals)
            labels.append(f"Baseline\n{pad}B")
        if pvals:
            data.append(pvals)
            labels.append(f"Protected\n{pad}B")

    if data:
        plt.figure(figsize=(max(8, len(labels) * 1.4), 6))
        plt.boxplot(data, labels=labels, showfliers=True)
        plt.ylabel("Login fetch time (ms)")
        plt.title("Baseline vs protected login fetch time")
        plt.xticks(rotation=20)
        plt.tight_layout()
        combined_path = out_dir / "login_fetch_boxplot_baseline_vs_protected.png"
        plt.savefig(combined_path, dpi=200, bbox_inches="tight")
        plt.close()
        print(f"[info] wrote {combined_path}")

    # One box plot per pad
    for pad in shared_pads:
        bvals = [r.get("login_fetch_ms") for r in baseline_by_pad[pad] if isinstance(r.get("login_fetch_ms"), (int, float)) and not isinstance(r.get("login_fetch_ms"), bool)]
        pvals = [r.get("login_fetch_ms") for r in protected_by_pad[pad] if isinstance(r.get("login_fetch_ms"), (int, float)) and not isinstance(r.get("login_fetch_ms"), bool)]
        if not bvals and not pvals:
            continue

        plot_data = []
        plot_labels = []
        if bvals:
            plot_data.append(bvals)
            plot_labels.append("Baseline")
        if pvals:
            plot_data.append(pvals)
            plot_labels.append("Protected")

        plt.figure(figsize=(6, 6))
        plt.boxplot(plot_data, labels=plot_labels, showfliers=True)
        plt.ylabel("Login fetch time (ms)")
        plt.title(f"Login fetch time box plot ({pad}B pad)")
        plt.tight_layout()
        pad_path = out_dir / f"login_fetch_boxplot_{pad}B.png"
        plt.savefig(pad_path, dpi=200, bbox_inches="tight")
        plt.close()
        print(f"[info] wrote {pad_path}")


def main():
    if len(sys.argv) != 2:
        print("usage: python3 parse_metrics.py metrics/metrics.ndjson", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    rows = load_ndjson(path)

    merged_login = merge_login_iterations(rows)

    baseline_login = [r for r in merged_login if r.get("kind") == "baseline-login"]
    protected_login = [r for r in merged_login if r.get("kind") == "protected-login"]

    baseline_by_pad = defaultdict(list)
    for r in baseline_login:
        baseline_by_pad[int(r.get("pad_bytes", 0))].append(r)

    protected_by_pad = defaultdict(list)
    for r in protected_login:
        protected_by_pad[int(r.get("pad_bytes", 0))].append(r)

    # ---------- Table 6.1 style ----------
    baseline_sections = []
    for pad in sorted(baseline_by_pad, key=pad_order_key):
        rows_pad = baseline_by_pad[pad]
        baseline_sections.append((
            f"Login (client + host), pad={pad}B",
            summarize_rows(rows_pad, [
                ("Login fetch time", "login_fetch_ms", "ms"),
                ("Login request JSON body bytes", "login_req_body_bytes", "B"),
                ("Host request header bytes", "host_req_header_bytes", "B"),
                ("Login response body bytes", "login_resp_body_bytes", "B"),
            ])
        ))

    baseline_big = collect_big_bundle_stats(rows, "baseline")
    baseline_sections.append((
        "Big content benchmark (host): unsigned bundle totals per page-load",
        summarize_rows(baseline_big, [
            ("Total baseline SW fetch time per bundle", "bundle_fetch_ms", "ms"),
            ("Total baseline SW processing time per bundle", "bundle_sw_total_ms", "ms"),
            ("Total bytes per bundle (headers+body)", "bundle_total_bytes", "B"),
            ("of which headers", "bundle_header_bytes", "B"),
            ("of which body", "bundle_body_bytes", "B"),
        ])
    ))
    print_metric_table("Table 6.1 style — Baseline performance", baseline_sections)

    # ---------- Table 6.2 style ----------
    protected_sections = []
    for pad in sorted(protected_by_pad, key=pad_order_key):
        rows_pad = protected_by_pad[pad]
        protected_sections.append((
            f"Pad = {pad}B",
            summarize_rows(rows_pad, [
                ("JWE encryption time", "jwe_encrypt_ms", "ms"),
                ("Login fetch time", "login_fetch_ms", "ms"),
                ("SW upstream fetch time", "sw_upstream_fetch_ms", "ms"),
                ("Host response signing time", "sign_ms", "ms"),
                ("SW verification time", "sw_verify_ms", "ms"),
                ("Host request verify time", "host_req_verify_ms", "ms"),
                ("Host decrypt time (total)", "host_decrypt_ms", "ms"),
                ("Request body size", "login_req_body_bytes", "B"),
                ("Header size", "host_req_header_bytes", "B"),
                ("Request-sign header size", "host_req_sign_header_bytes", "B"),
                ("SW request-sign time", "sw_req_sign_ms", "ms"),
                ("SW request-sign digest time", "sw_req_sign_digest_ms", "ms"),
                ("SW request-sign signature time", "sw_req_sign_signature_ms", "ms"),
                ("SW request-sign header bytes", "sw_req_sign_header_bytes", "B"),
            ])
        ))
    print_metric_table("Table 6.2 style — Proposed solution login performance", protected_sections)

    # ---------- bootstrap table ----------
    bootstrap_rows = [r for r in rows if r.get("event") == "req_sign_bootstrap"]
    bootstrap_sections = [(
        "Request-sign bootstrap",
        summarize_rows(bootstrap_rows, [
            ("SW request-sign keygen time", "sw_req_keygen_ms", "ms"),
            ("SW request-sign key export time", "sw_req_key_export_ms", "ms"),
            ("SW request-sign key total time", "sw_req_key_total_ms", "ms"),
            ("Register payload bytes", "req_key_register_payload_bytes", "B"),
            ("Register JWE bytes", "req_key_register_jwe_bytes", "B"),
            ("Register JWE encryption time", "req_key_register_jwe_encrypt_ms", "ms"),
            ("Register fetch time", "req_key_register_fetch_ms", "ms"),
            ("Total bootstrap time", "req_sign_bootstrap_total_ms", "ms"),
        ])
    )]
    print_metric_table("New table — Request-sign bootstrap", bootstrap_sections)

    # ---------- Table 6.3 style ----------
    protected_big = collect_big_bundle_stats(rows, "protected")
    protected_big_sections = [(
        "Protected big-content benchmark (signed bundle totals per page-load)",
        summarize_rows(protected_big, [
            ("Total SW upstream fetch time per bundle", "bundle_fetch_ms", "ms"),
            ("Total signing time per bundle", "bundle_sign_ms", "ms"),
            ("Total SW verification time per bundle", "bundle_sw_verify_ms", "ms"),
            ("Total SW processing time per bundle", "bundle_sw_total_ms", "ms"),
            ("Total SW request-sign time per bundle", "bundle_sw_req_sign_ms", "ms"),
            ("Total request-sign header bytes per bundle", "bundle_sw_req_sign_header_bytes", "B"),
            ("Total bytes per bundle (headers+body)", "bundle_total_bytes", "B"),
            ("of which headers", "bundle_header_bytes", "B"),
            ("of which body", "bundle_body_bytes", "B"),
        ])
    )]
    print_metric_table("Table 6.3 style — Proposed solution big-content benchmark", protected_big_sections)

    # ---------- Table 6.4 style ----------
    compare_rows = []
    all_pads = sorted(set(baseline_by_pad) & set(protected_by_pad))
    for pad in all_pads:
        b = baseline_by_pad[pad]
        p = protected_by_pad[pad]

        compare_rows.append((
            f"Login fetch time, pad={pad}B",
            mean([x.get("login_fetch_ms") for x in b if x.get("login_fetch_ms") is not None]),
            mean([x.get("login_fetch_ms") for x in p if x.get("login_fetch_ms") is not None]),
            "ms"
        ))
        compare_rows.append((
            f"Login request JSON body size, pad={pad}B",
            mean([x.get("login_req_body_bytes") for x in b if x.get("login_req_body_bytes") is not None]),
            mean([x.get("login_req_body_bytes") for x in p if x.get("login_req_body_bytes") is not None]),
            "B"
        ))
        compare_rows.append((
            f"Host request header size, pad={pad}B",
            mean([x.get("host_req_header_bytes") for x in b if x.get("host_req_header_bytes") is not None]),
            mean([x.get("host_req_header_bytes") for x in p if x.get("host_req_header_bytes") is not None]),
            "B"
        ))
        compare_rows.append((
            f"Host response signing time, pad={pad}B",
            0.0,
            mean([x.get("sign_ms") for x in p if x.get("sign_ms") is not None]),
            "ms"
        ))

    print_compare_table("Table 6.4 style — Baseline vs proposed overhead", compare_rows)

    # ---------- new big comparison table ----------
    big_compare_rows = []
    if baseline_big and protected_big:
        big_compare_rows.extend([
            (
                "Big bundle fetch time",
                mean([x.get("bundle_fetch_ms") for x in baseline_big if x.get("bundle_fetch_ms") is not None]),
                mean([x.get("bundle_fetch_ms") for x in protected_big if x.get("bundle_fetch_ms") is not None]),
                "ms"
            ),
            (
                "Big bundle total SW processing time",
                mean([x.get("bundle_sw_total_ms") for x in baseline_big if x.get("bundle_sw_total_ms") is not None]),
                mean([x.get("bundle_sw_total_ms") for x in protected_big if x.get("bundle_sw_total_ms") is not None]),
                "ms"
            ),
            (
                "Big bundle total bytes",
                mean([x.get("bundle_total_bytes") for x in baseline_big if x.get("bundle_total_bytes") is not None]),
                mean([x.get("bundle_total_bytes") for x in protected_big if x.get("bundle_total_bytes") is not None]),
                "B"
            ),
            (
                "Big bundle header bytes",
                mean([x.get("bundle_header_bytes") for x in baseline_big if x.get("bundle_header_bytes") is not None]),
                mean([x.get("bundle_header_bytes") for x in protected_big if x.get("bundle_header_bytes") is not None]),
                "B"
            ),
            (
                "Big bundle body bytes",
                mean([x.get("bundle_body_bytes") for x in baseline_big if x.get("bundle_body_bytes") is not None]),
                mean([x.get("bundle_body_bytes") for x in protected_big if x.get("bundle_body_bytes") is not None]),
                "B"
            ),
            (
                "Big bundle signing time",
                0.0,
                mean([x.get("bundle_sign_ms") for x in protected_big if x.get("bundle_sign_ms") is not None]),
                "ms"
            ),
            (
                "Big bundle SW verification time",
                0.0,
                mean([x.get("bundle_sw_verify_ms") for x in protected_big if x.get("bundle_sw_verify_ms") is not None]),
                "ms"
            ),
        ])

    print_compare_table("New table — Baseline vs proposed big-content overhead", big_compare_rows)

    # ---------- plots ----------
    plot_dir = path.parent / "plots"
    make_login_fetch_boxplots(baseline_by_pad, protected_by_pad, plot_dir)


if __name__ == "__main__":
    main()
