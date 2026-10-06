#!/usr/bin/env python3
"""Generate a preview of ordinal performance-ranking tables.

This is deliberately not part of ``make build`` yet.  It reads one published
campaign from an ngcc-harness checkout and the synchronized vulnerability
reports from this repository, then writes a Markdown page containing HTML
tables.  Example:

    python3 tools/rank_performance.py ../ngcc-harness \
        --system x86_1 --output-dir /tmp/ngcc-rankings

Every metric is ranked independently, with tied values receiving their average
ordinal rank.  The overall score is the arithmetic mean of those ranks.  Only
instances with every metric required by their category enter a table, so a
missing measurement is never rewarded.  Security findings are displayed but
do not affect the performance ordering.  The three generated pages compare
only instances assigned to the same NGCC target in
``performance/security_targets.csv``.  The pages are named
``ranking-128.md``, ``ranking-256.md`` and ``ranking-512.md``.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


CATEGORIES = (
    ("sign", "Digital Signatures"),
    ("kem", "Key Encapsulation"),
    ("kex", "Key Exchange"),
    ("hash", "Hash Functions"),
)
TARGETS = (128, 256, 512)

# Key generation and secret-key size are intentionally absent.  A signature or
# KEM key can be generated once and reused, generated ahead of an ephemeral
# exchange, or represented by a short deterministic seed.
METRICS = {
    "sign": (
        ("sign_cycles", "sign cycles", "cycles"),
        ("verify_cycles", "verify cycles", "cycles"),
        ("pk_bytes", "public key", "bytes"),
        ("signature_bytes", "signature", "bytes"),
    ),
    "kem": (
        ("enc_cycles", "encapsulate cycles", "cycles"),
        ("dec_cycles", "decapsulate cycles", "cycles"),
        ("pk_bytes", "public key", "bytes"),
        ("ct_bytes", "ciphertext", "bytes"),
    ),
    "kex": (
        ("exchange_cycles", "exchange cycles", "cycles"),
        ("bandwidth_bytes", "bandwidth", "bytes"),
    ),
    "hash": (
        ("hash_32_cycles", "32 B cycles", "cycles"),
        ("hash_1024_cycles", "1 KiB cycles", "cycles"),
        ("hash_65536_cycles", "64 KiB cycles", "cycles"),
    ),
}

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_INDEX = {severity: index for index, severity in enumerate(SEVERITIES)}
ISSUE_HEADING = re.compile(r"^## ((?:sign|kem|kex|hash)-\d{2}-\d+): ")
META = re.compile(r"^(Severity|Status):\s*(.+?)\s*$")


def read_csv(path: Path, delimiter: str = ";") -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as source:
        return list(csv.DictReader((line for line in source if not line.startswith("#")),
                                   delimiter=delimiter))


def natural(value: str) -> tuple:
    return tuple(int(token) if token.isdigit() else token.lower()
                 for token in re.split(r"(\d+)", value))


def fmt_number(value: float, unit: str) -> str:
    if unit == "bytes":
        return f"{int(value):,} B"
    if value >= 1e9:
        return f"{value / 1e9:.2f} G"
    if value >= 1e6:
        return f"{value / 1e6:.2f} M"
    if value >= 1e4:
        return f"{value / 1e3:.1f} k"
    return f"{value:.0f}"


def fmt_percent(value: float | None) -> str:
    if value is None:
        return "??%"
    return f"{100 * value:.0f}%" if value >= 0.095 else f"{100 * value:.1f}%"


@dataclass
class Entry:
    candidate: str
    label: str
    category: str
    target_bits: int
    values: dict[str, float] = field(default_factory=dict)
    hash_shares: dict[str, float] = field(default_factory=dict)
    xof_ratios: dict[str, float] = field(default_factory=dict)
    size_basis: str = "encoded"
    ranks: dict[str, float] = field(default_factory=dict)
    mean_rank: float = 0.0

    @property
    def key(self) -> tuple[str, str]:
        return self.candidate, self.label

    @property
    def display(self) -> str:
        # Do not synthesize sign-01-1-like identifiers: those are stable
        # vulnerability IDs.  Candidate/instance is unambiguous.
        return f"{self.candidate}/{self.label}"


def load_profiles(run_dir: Path) -> dict[tuple[str, str], dict[str, dict]]:
    profiles: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)
    for path in sorted((run_dir / "profile").glob("*/*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        operation = record.get("operation")
        if operation:
            profiles[(record["candidate"], record["label"])][operation] = record
    return profiles


def load_targets(path: Path) -> dict[tuple[str, str], int | None]:
    rows = read_csv(path)
    if not rows or tuple(rows[0]) != ("ID", "Instance", "TargetBits"):
        raise ValueError(f"{path}: expected ID;Instance;TargetBits")
    targets: dict[tuple[str, str], int | None] = {}
    allowed = {str(target) for target in TARGETS}
    for line_number, row in enumerate(rows, 2):
        key = row["ID"], row["Instance"]
        if key in targets:
            raise ValueError(f"{path}:{line_number}: duplicate {key[0]}/{key[1]}")
        value = row["TargetBits"]
        if value and value not in allowed:
            raise ValueError(f"{path}:{line_number}: invalid target {value!r}")
        targets[key] = int(value) if value else None
    return targets


def load_kex_bandwidth(path: Path) -> dict[tuple[str, str], int]:
    rows = read_csv(path)
    if not rows or tuple(rows[0]) != ("ID", "Instance", "PkABytes", "PkBBytes", "ProtocolMessageBytes"):
        raise ValueError(f"{path}: invalid KEX bandwidth header")
    bandwidth = {}
    for row in rows:
        key = row["ID"], row["Instance"]
        if key in bandwidth:
            raise ValueError(f"{path}: duplicate {key[0]}/{key[1]}")
        messages, pk_a, pk_b = (int(row[name]) for name in
                               ("ProtocolMessageBytes", "PkABytes", "PkBBytes"))
        if min(messages, pk_a, pk_b) < 0:
            raise ValueError(f"{path}: negative size for {key[0]}/{key[1]}")
        bandwidth[key] = messages + pk_a + pk_b
    return bandwidth


def load_external_sizes(path: Path) -> dict[tuple[str, str], dict[str, str]]:
    rows = read_csv(path)
    if not rows or tuple(rows[0]) != (
            "ID", "Instance", "PublicKeyBytes", "CiphertextBytes", "SignatureBytes", "Basis"):
        raise ValueError(f"{path}: invalid external-size header")
    sizes = {}
    for row in rows:
        key = row["ID"], row["Instance"]
        if key in sizes:
            raise ValueError(f"{path}: duplicate {key[0]}/{key[1]}")
        sizes[key] = row
    return sizes


def load_entries(harness: Path, system: str) -> list[Entry]:
    run_dir = harness / "performance" / "data" / system
    records_dir = run_dir / "records"
    build_path = run_dir / "build.json"
    if not records_dir.is_dir() or not build_path.is_file():
        raise ValueError(f"{run_dir}: incomplete performance dataset")

    build = json.loads(build_path.read_text(encoding="utf-8")).get("instances", {})
    survey = {row["ID"]: row for row in
              read_csv(harness / "performance" / "symmetric_survey.csv")}
    profiles = load_profiles(run_dir)
    targets = load_targets(harness / "performance" / "security_targets.csv")
    kex_bandwidth = load_kex_bandwidth(harness / "performance" / "kex_bandwidth.csv")
    external_sizes = load_external_sizes(harness / "performance" / "external_sizes.csv")
    xof_baseline = {}
    for path in sorted((records_dir / "iccs").glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        match = re.fullmatch(r"pseudoXOF-(\d+)", record.get("label", ""))
        if match and record.get("status") == "complete" and record.get("mean_cycles"):
            xof_baseline[(int(record.get("input_bytes") or 0), int(match.group(1)))] = \
                float(record["mean_cycles"])
    entries: dict[tuple[str, str], Entry] = {}

    for path in sorted(records_dir.glob("*/*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("status") != "complete" or record.get("candidate") == "iccs":
            continue
        candidate, label = record["candidate"], record["label"]
        category = candidate.split("-", 1)[0]
        if category not in METRICS:
            continue
        build_key = f"{candidate}/{label}"
        if build_key not in build:
            raise ValueError(f"{build_path}: missing build entry for {build_key}")
        build_entry = build[build_key]
        if build_entry.get("variant", "reference") != "reference":
            continue
        target_key = candidate, label
        if target_key not in targets:
            raise ValueError(f"performance/security_targets.csv: missing {candidate}/{label}")
        target_bits = targets[target_key]
        if target_bits is None:
            continue
        entry = entries.setdefault(
            target_key, Entry(candidate, label, category, target_bits))
        operation = record["operation"]
        input_bytes = int(record.get("input_bytes") or 0)
        metric = f"hash_{input_bytes}_cycles" if category == "hash" else f"{operation}_cycles"
        if record.get("mean_cycles") is not None:
            entry.values[metric] = float(record["mean_cycles"])
        if category == "hash":
            digest_bits = 8 * int((record.get("sizes") or {}).get("digest_bytes") or 0)
            baseline = xof_baseline.get((input_bytes, digest_bits))
            if baseline and record.get("mean_cycles") is not None:
                entry.xof_ratios[metric] = float(record["mean_cycles"]) / baseline
        else:
            profile = profiles.get(entry.key, {}).get(operation)
            if profile is not None and profile.get("hash_share") is not None:
                entry.hash_shares[metric] = float(profile["hash_share"])
        for name, value in (record.get("sizes") or {}).items():
            if value not in (None, 0, "0", ""):
                entry.values[name] = float(value)

    for entry in entries.values():
        if entry.category == "kex":
            if entry.key not in kex_bandwidth:
                raise ValueError(f"performance/kex_bandwidth.csv: missing {entry.display}")
            entry.values["bandwidth_bytes"] = float(kex_bandwidth[entry.key])
        elif entry.category in ("kem", "sign"):
            if entry.key not in external_sizes:
                raise ValueError(f"performance/external_sizes.csv: missing {entry.display}")
            sizes = external_sizes[entry.key]
            entry.values["pk_bytes"] = float(sizes["PublicKeyBytes"])
            name = "ct_bytes" if entry.category == "kem" else "signature_bytes"
            column = "CiphertextBytes" if entry.category == "kem" else "SignatureBytes"
            entry.values[name] = float(sizes[column])
            entry.size_basis = sizes["Basis"]

    # Match the aggregate performance page: omit a zero-placeholder backend
    # only when the same candidate has an ICCS-facing measured backend.  If no
    # such backend exists, keep the candidate and mark its share unavailable;
    # its own symmetric primitives cannot be decomposed as an ICCS share.
    candidate_has_iccs = set()
    zero_placeholder = set()
    for entry in entries.values():
        if entry.category == "hash":
            continue
        required_ops = [name.removesuffix("_cycles") for name, _, _ in METRICS[entry.category]
                        if name.endswith("_cycles")]
        shares = [profiles[entry.key][op].get("hash_share") for op in required_ops
                  if op in profiles.get(entry.key, {}) and
                  profiles[entry.key][op].get("hash_share") is not None]
        if shares and all(share == 0 for share in shares):
            zero_placeholder.add(entry.key)
        elif any(share > 0 for share in shares):
            candidate_has_iccs.add(entry.candidate)

    kept = []
    for entry in entries.values():
        verdict = survey.get(entry.candidate, {}).get("Verdict", "")
        if (entry.key in zero_placeholder and verdict != "ICCS-only" and
                entry.candidate in candidate_has_iccs):
            continue
        if entry.key in zero_placeholder and entry.candidate not in candidate_has_iccs:
            entry.hash_shares.clear()
        kept.append(entry)
    return kept


def load_security(report_dir: Path) -> dict[str, Counter]:
    findings: dict[str, Counter] = defaultdict(Counter)
    for path in sorted(report_dir.glob("*.md")):
        candidate = path.stem
        current = None
        meta: dict[str, str] = {}

        def finish() -> None:
            nonlocal current, meta
            if not current:
                return
            severity = meta.get("Severity", "").lower()
            status = meta.get("Status", "").lower()
            if severity in SEVERITY_INDEX and status != "withdrawn":
                findings[candidate][severity] += 1
            current, meta = None, {}

        for line in path.read_text(encoding="utf-8").splitlines():
            if ISSUE_HEADING.match(line):
                finish()
                current = line
            elif current and (match := META.match(line)):
                meta[match.group(1)] = match.group(2)
        finish()
    return findings


def load_names(data_dir: Path) -> dict[str, tuple[str, str]]:
    official = {}
    for category, _ in CATEGORIES:
        for row in read_csv(data_dir / f"{category}.csv"):
            candidate = f"{category}-{int(row['No']):02d}"
            official[candidate] = row["Algorithm"]
    short = {}
    for line_number, row in enumerate(read_csv(data_dir / "short_names.csv"), 2):
        candidate, value = row["ID"], row["ShortName"]
        if candidate in short or not re.fullmatch(r"[A-Za-z0-9-]+", value):
            raise ValueError(f"short_names.csv:{line_number}: invalid row")
        short[candidate] = value
    if set(short) != set(official):
        raise ValueError("short_names.csv does not cover every candidate exactly once")
    return {candidate: (short[candidate], name) for candidate, name in official.items()}


def assign_ranks(entries: list[Entry], metric_names: list[str]) -> list[Entry]:
    eligible = [entry for entry in entries if all(name in entry.values for name in metric_names)]
    for metric in metric_names:
        ordered = sorted(eligible, key=lambda entry: (entry.values[metric], natural(entry.display)))
        start = 0
        while start < len(ordered):
            end = start + 1
            while end < len(ordered) and ordered[end].values[metric] == ordered[start].values[metric]:
                end += 1
            rank = ((start + 1) + end) / 2
            for entry in ordered[start:end]:
                entry.ranks[metric] = rank
            start = end
    for entry in eligible:
        entry.mean_rank = sum(entry.ranks[name] for name in metric_names) / len(metric_names)
    return eligible


def select_fastest(entries: list[Entry], category: str) -> list[Entry]:
    """Keep one comparison-eligible reference instance per candidate and target.

    performance/security_targets.csv first decides which parameter sets are
    eligible.  Thus an optional parameter set cannot displace a submitter's
    designated primary set merely by being faster.  If more than one eligible
    reference instance remains, selection uses only cycle metrics: sizes
    participate in the final ordering, but do not cause a slower instance to
    represent a candidate.  As elsewhere on the page, tied cycle values receive
    their average ordinal position.
    """
    metrics = METRICS[category]
    required = [name for name, _, _ in metrics]
    cycle_metrics = [name for name, _, unit in metrics if unit == "cycles"]
    eligible = [entry for entry in entries if all(name in entry.values for name in required)]
    cycle_ranks: dict[tuple[str, str], dict[str, float]] = defaultdict(dict)
    for metric in cycle_metrics:
        ordered = sorted(eligible, key=lambda entry: (entry.values[metric], natural(entry.display)))
        start = 0
        while start < len(ordered):
            end = start + 1
            while end < len(ordered) and ordered[end].values[metric] == ordered[start].values[metric]:
                end += 1
            rank = ((start + 1) + end) / 2
            for entry in ordered[start:end]:
                cycle_ranks[entry.key][metric] = rank
            start = end
    by_candidate: dict[str, list[Entry]] = defaultdict(list)
    for entry in eligible:
        by_candidate[entry.candidate].append(entry)
    selected = []
    for candidate in sorted(by_candidate, key=natural):
        choices = by_candidate[candidate]
        selected.append(min(
            choices,
            key=lambda entry: (
                sum(cycle_ranks[entry.key][metric] for metric in cycle_metrics) /
                len(cycle_metrics),
                natural(entry.label))))
    return selected


def security_badge(candidate: str, findings: dict[str, Counter]) -> str:
    counts = findings.get(candidate, Counter())
    severity = next((value for value in SEVERITIES if counts[value]), "none")
    count = counts[severity] if severity != "none" else 0
    summary = ", ".join(f"{counts[value]} {value}" for value in SEVERITIES if counts[value])
    title = html.escape(summary or "no active published finding", quote=True)
    href = f"../../reports/{candidate}.md"
    return (f'<a href="{href}" class="sev sev-{severity}" title="{title}">'
            f'{count}</a>')


def entry_link(entry: Entry) -> str:
    title = html.escape(entry.label, quote=True)
    return (f'<a href="{entry.candidate}.md" title="{title}">'
            f'<code>{html.escape(entry.candidate)}</code></a>')


def render_table(category: str, title: str, entries: list[Entry],
                 findings: dict[str, Counter], names: dict[str, tuple[str, str]],
                 target_bits: int) -> str:
    metrics = METRICS[category]
    metric_names = [name for name, _, _ in metrics]
    eligible = assign_ranks(select_fastest(entries, category), metric_names)
    overall = sorted(eligible, key=lambda entry: (entry.mean_rank, natural(entry.display)))
    columns = [overall] + [sorted(eligible,
                                  key=lambda entry, metric=name:
                                  (entry.values[metric], natural(entry.display)))
                           for name in metric_names]
    headers = ["rank", "overall (mean rank)"] + [label for _, label, _ in metrics]
    lines = [f"## {title} ({target_bits}-bit security)", "",
             '<div class="ranking-table"><table>',
             "<thead><tr>" + "".join(f"<th>{html.escape(header)}</th>" for header in headers) +
             "</tr></thead>", "<tbody>"]
    for index in range(len(eligible)):
        cells = [str(index + 1)]
        entry = columns[0][index]
        components = ", ".join(
            f"{label}: {entry.ranks[name]:g}"
            for name, label, _ in metrics)
        rank_title = html.escape(
            f"mean rank {entry.mean_rank:.1f}; {components}", quote=True)
        compact, official = names.get(entry.candidate, ("", ""))
        algorithm = html.escape(compact)
        if compact != official:
            algorithm = (f'<span title="{html.escape(official, quote=True)}">'
                         f'{algorithm}</span>')
        cells.append(f'<span title="{rank_title}">({entry.mean_rank:.1f}) '
                     f'{entry_link(entry)} {algorithm}</span> ' +
                     security_badge(entry.candidate, findings))
        for metric, column, (_, _, unit) in zip(metric_names, columns[1:], metrics):
            entry = column[index]
            compact, official = names[entry.candidate]
            algorithm = html.escape(compact)
            if compact != official:
                algorithm = (f'<span title="{html.escape(official, quote=True)}">'
                             f'{algorithm}</span>')
            rendered = fmt_number(entry.values[metric], unit)
            if unit == "cycles":
                if category == "hash":
                    ratio = entry.xof_ratios.get(metric)
                    rendered += " (ratio –)" if ratio is None else f" ({ratio:.2f}×)"
                else:
                    rendered += f" ({fmt_percent(entry.hash_shares.get(metric))})"
            elif category == "sign" and metric == "signature_bytes" and \
                    entry.size_basis == "nominal-variable":
                rendered = "≈" + rendered
            cells.append(f"{rendered} {entry_link(entry)} {algorithm}")
        lines.append("<tr>" + "".join(f"<td>{cell}</td>" for cell in cells) + "</tr>")
    lines += ["</tbody></table></div>", ""]
    return "\n".join(lines)


def render(entries: list[Entry], findings: dict[str, Counter],
           names: dict[str, tuple[str, str]],
           systems: tuple[str, ...], system: str, target_bits: int) -> str:
    system_links = []
    for candidate in systems:
        if candidate == system:
            system_links.append(
                f'<a href="index.md"><strong>{html.escape(candidate)}</strong></a>')
        else:
            system_links.append(
                f'<a href="../{html.escape(candidate)}/index.md">'
                f'{html.escape(candidate)}</a>')
    selector = (f'<p class="crumb"><a href="../index.md">Performance measurements</a> › '
                f'system: {" · ".join(system_links)}</p>')
    links = []
    for target in TARGETS:
        name = f"ranking-{target}.md"
        links.append(f"[{target}-bit]({name})" if target != target_bits else f"**{target}-bit**")
    sections = [selector, "", f"# Ordered measurements ({system}, {target_bits}-bit)", "",
                "Target: " + " · ".join(links), "",
                "- **Order:** each metric is ranked separately; overall is their mean rank. "
                "Lower is better, and ties share the average position.",
                f"- **Scope:** eligible reference instances at the {target_bits}-bit target. "
                "The recommended set represents a candidate; otherwise the fastest eligible "
                "set by mean cycle rank does. Key generation and secret-key size are excluded.",
                "- **Cycles:** `(hash %)` is time in ICCS placeholder hashes; `(??%)` means "
                "no ICCS-facing backend was measured. Hash `×` values compare with the matching `pseudoXOF`.",
                "- **Bytes:** KEX bandwidth includes exchanged public keys. KEM public-key size is "
                "separate from ciphertext size. `≈` marks a nominal variable-length signature. "
                "See the [size audit](../external-size-audit.md) for accounting details.",
                "- **Security badge:** number of active findings at the candidate's highest "
                "severity; it does not affect the order.", ""]
    for category, title in CATEGORIES:
        category_entries = [entry for entry in entries
                            if entry.category == category and entry.target_bits == target_bits]
        sections.append(render_table(
            category, title, category_entries, findings, names, target_bits))
    return "\n".join(sections).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", type=Path, help="path to the ngcc-harness checkout")
    parser.add_argument("--system", default="x86_1", help="performance system identifier")
    parser.add_argument("--reports", type=Path,
                        default=Path(__file__).resolve().parent.parent / "content" / "reports",
                        help="directory containing synchronized candidate reports")
    parser.add_argument("--candidate-data", type=Path,
                        default=Path(__file__).resolve().parent.parent / "content" / "data",
                        help="directory containing sign.csv, kem.csv, kex.csv and hash.csv")
    outputs = parser.add_mutually_exclusive_group()
    outputs.add_argument("--output", type=Path, help="write one target page here instead of stdout")
    outputs.add_argument("--output-dir", type=Path,
                         help="write ranking-128.md, ranking-256.md and ranking-512.md here")
    parser.add_argument("--target", type=int, choices=TARGETS, default=256,
                        help="target for stdout or --output (default: 256)")
    args = parser.parse_args()
    harness = args.harness.resolve()
    systems = tuple(
        row["ID"] for row in read_csv(harness / "performance" / "systems.csv")
        if (harness / "performance" / f"summary_{row['ID']}.md").is_file()
    )
    if args.system not in systems:
        raise ValueError(f"{args.system}: no published performance summary")
    entries = load_entries(harness, args.system)
    findings = load_security(args.reports.resolve())
    names = load_names(args.candidate_data.resolve())
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for target in TARGETS:
            name = f"ranking-{target}.md"
            (args.output_dir / name).write_text(
                render(entries, findings, names, systems, args.system, target), encoding="utf-8")
        print(f"ranking preview: {len(entries)} measured reference instances -> {args.output_dir}")
    elif args.output:
        output = render(entries, findings, names, systems, args.system, args.target)
        args.output.write_text(output, encoding="utf-8")
        print(f"ranking preview: {len(entries)} measured reference instances -> {args.output}")
    else:
        sys.stdout.write(render(entries, findings, names, systems, args.system, args.target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
