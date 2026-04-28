#!/usr/bin/env python3
r"""
Jigsaw XDR+ OmniParser CLI
Author: Kennedy Aikohi
LinkedIn: linkedin.com/in/aikohikennedy
GitHub: github.com/kennedy-aikohi

Jigsaw-style usage:
  python jigsaw_cli.py hunt C:\Logs --json out\hits.json --csv out\hits.csv --report out\report.txt
  python jigsaw_cli.py hunt C:\Logs\Security.evtx C:\Logs\sysmon.jsonl --event-ids 1,3,7,4688 --keyword powershell
"""
import argparse
import csv
import json
from pathlib import Path
import sys

from jigsaw import JigsawEngine, JIGSAW_RULES, PRODUCT_NAME, PRODUCT_VERSION, AUTHOR_NAME, AUTHOR_LINKEDIN, AUTHOR_GITHUB, SEV_ORDER


def parse_event_ids(raw):
    if not raw:
        return []
    out = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            out.append(int(item))
    return out


def render_report(events, hits, stats):
    a = stats.get("analysis", {})
    lines = [
        f"{PRODUCT_NAME} v{PRODUCT_VERSION} — CLI Analysis Results",
        f"Author: {AUTHOR_NAME} | LinkedIn: {AUTHOR_LINKEDIN} | GitHub: {AUTHOR_GITHUB}",
        "=" * 78,
        f"Events parsed : {len(events):,}",
        f"Raw records   : {stats.get('raw_total', len(events)):,}",
        f"Normalized    : {stats.get('normalized_total', len(events)):,}",
        f"Visible rows  : {stats.get('visible_total', len(events)):,}",
        f"Hidden/filter : {stats.get('hidden_by_filters', 0):,}",
        f"Parser errors : {stats.get('parser_errors', 0):,}",
        f"Active filters: {'; '.join(stats.get('filter_summary', ['unknown']))}",
        f"Hits detected : {len(hits):,}",
        f"Risk verdict  : {a.get('verdict', 'N/A')} ({a.get('risk_score', 0)}/100)",
        f"First seen    : {a.get('first_seen', '')}",
        f"Last seen     : {a.get('last_seen', '')}",
        "",
        "Severity distribution:",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"  {sev:<9} {stats.get('severity_dist', {}).get(sev, 0)}")

    def table(title, rows):
        lines.append("")
        lines.append(title + ":")
        if not rows:
            lines.append("  <none>")
        for k, v in rows:
            lines.append(f"  {str(k)[:54]:<54} {v}")

    table("Top rules", a.get("top_rules", []))
    table("Top event IDs", a.get("top_event_ids", []))
    table("Top computers", a.get("top_computers", []))
    table("Top channels", a.get("top_channels", []))
    table("Top processes", a.get("top_processes", []))
    lines.append("")
    lines.append("Attack-chain hunting map:")
    ac = a.get("attack_chain", {})
    for stage, count, state in ac.get("stages", []):
        lines.append(f"  {stage:<32} {count:>4} {state}")
    if ac.get("coverage"):
        lines.append("Telemetry coverage parsed:")
        for row in ac.get("coverage", []):
            lines.append("  - " + row)

    diagnostics = stats.get("diagnostics", [])
    if diagnostics:
        lines.append("")
        lines.append("Per-file parser proof:")
        for d in diagnostics[:50]:
            status = "ERROR" if d.get("status") == "error" else "OK"
            lines.append(f"  [{status}] {d.get('file','')}: raw={d.get('raw',0):,}, normalized={d.get('normalized',0):,}, visible={d.get('visible',0):,}, parser={d.get('parser','')}")
            if d.get("error"):
                lines.append(f"        error: {d.get('error')}")
        if len(diagnostics) > 50:
            lines.append(f"  ... {len(diagnostics)-50} more files omitted")
    if stats.get("raw_total", 0) and not stats.get("visible_total", len(events)):
        lines.append("")
        lines.append("Conclusion: raw records were parsed, but active filters hid every visible event. Clear filters / run without --event-ids, --keyword, --regex, --ip, or --process-guid.")
    elif not stats.get("raw_total", len(events)):
        lines.append("")
        lines.append("Conclusion: no raw records were parsed. Verify parser dependencies, empty/corrupt files, or export XML/JSON as fallback.")
    elif not hits:
        lines.append("")
        lines.append("Conclusion: parsing works and events are visible, but no enabled detection rule matched them.")

    lines.append("")
    lines.append("Recommended next actions:")
    for r in a.get("recommendations", []):
        lines.append("  - " + r)
    if hits:
        lines.append("")
        lines.append("Highest priority detections:")
        for h in sorted(hits, key=lambda x: SEV_ORDER.get(x["severity"], 9))[:50]:
            lines.append(f"  [{h['severity']}] {h['rule_id']} {h['rule_name']} | EID {h['event_id']} | {h['detail'][:220]}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        prog="jigsaw",
        description=f"{PRODUCT_NAME} v{PRODUCT_VERSION}: offline Windows log parser and detection engine by {AUTHOR_NAME}",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    hunt = sub.add_parser("hunt", help="Parse logs and run detections")
    hunt.add_argument("paths", nargs="+", help="Files or directories: EVTX, EVT, XML, JSON, JSONL, CSV, TXT, LOG")
    hunt.add_argument("--event-ids", default="", help="Comma-separated Event IDs, e.g. 1,3,7,4688")
    hunt.add_argument("--keyword", default="", help="Case-insensitive keyword filter")
    hunt.add_argument("--regex", default="", help="Regex filter")
    hunt.add_argument("--ip", default="", help="IP correlation filter")
    hunt.add_argument("--process-guid", default="", help="ProcessGuid trace filter")
    hunt.add_argument("--disable-rule", action="append", default=[], help="Disable a rule ID. Repeat as needed.")
    hunt.add_argument("--only-rule", action="append", default=[], help="Run only the specified rule ID(s). Repeat as needed.")
    hunt.add_argument("--json", dest="json_out", help="Write detection hits as JSON")
    hunt.add_argument("--csv", dest="csv_out", help="Write detection hits as CSV")
    hunt.add_argument("--report", dest="report_out", help="Write human-readable analysis report")
    hunt.add_argument("--events-json", dest="events_json", help="Write parsed/filtered events as JSON")
    args = parser.parse_args()

    rules = {r["id"] for r in JIGSAW_RULES}
    if args.only_rule:
        rules = {r.upper() for r in args.only_rule}
    for rid in args.disable_rule:
        rules.discard(rid.upper())

    filters = {}
    if args.event_ids:
        filters["event_ids"] = parse_event_ids(args.event_ids)
    if args.keyword:
        filters["keyword"] = args.keyword
    if args.regex:
        filters["regex"] = args.regex
    if args.process_guid:
        filters["process_guid"] = args.process_guid

    def log(msg, lvl="info"):
        print(msg, file=sys.stderr)

    engine = JigsawEngine(log_cb=log)
    events, hits, stats = engine.parse_files(args.paths, filters, rules, ip_filter=args.ip)

    report = render_report(events, hits, stats)
    print(report)

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(hits, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.events_json:
        Path(args.events_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.events_json).write_text(json.dumps(events, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.report_out:
        Path(args.report_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_out).write_text(report, encoding="utf-8")
    if args.csv_out:
        Path(args.csv_out).parent.mkdir(parents=True, exist_ok=True)
        keys = ["rule_id", "rule_name", "severity", "category", "mitre", "timestamp", "event_id", "computer", "channel", "process", "image", "detail"]
        with open(args.csv_out, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            w.writerows(hits)

    # Exit 2 when detections are found so SOC pipelines can alert.
    return 2 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
