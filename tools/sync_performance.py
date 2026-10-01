#!/usr/bin/env python3
"""Copy generated harness performance reports into content/performance/.

    python3 tools/sync_performance.py /path/to/ngcc-harness

Every registered system with a generated summary contributes its all-candidate
summary, method page and one page per candidate. Relative links among copied
pages are rewritten for the website layout. The destination directory is
replaced only after the source inventory has been validated.
"""
import csv
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "content" / "performance"
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
SUMMARY_ROW_RE = re.compile(
    r"^\| \[([a-z]+-[0-9]{2})\]\(([^)]+)\) \| (.*?) \[PDF\]\([^)]+\) \| ([^|]+?)( \| )",
    re.M)
HARNESS_REV = "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af"
HARNESS_RAW = f"https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@{HARNESS_REV}"
ORDERED_TARGETS = (128, 256, 512)


def rows(path):
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader((line for line in f if not line.startswith("#")), delimiter=";"))


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python3 tools/sync_performance.py /path/to/ngcc-harness")
    src = Path(sys.argv[1]).resolve()
    registry = src / "performance" / "systems.csv"
    downloads = src / "downloads.csv"
    if not registry.is_file() or not downloads.is_file():
        sys.exit(f"sync-performance: {src} is not a complete harness checkout")
    systems = [row for row in rows(registry)
               if (src / "performance" / f"summary_{row['ID']}.md").is_file()]
    if not systems:
        sys.exit("sync-performance: no performance/summary_<ID>.md found")
    candidate_ids = {row["ID"] for row in rows(downloads)}

    # harness path -> site path, both relative to their repository roots
    site_of = {"performance/symmetric-survey.md": "performance/symmetric-survey.md"}
    for row in systems:
        sid = row["ID"]
        pages = {page.parent.name: page for page in src.glob(f"*-[0-9][0-9]/perf_{sid}.md")}
        missing = sorted(candidate_ids - pages.keys())
        extra = sorted(pages.keys() - candidate_ids)
        if missing or extra:
            sys.exit(f"sync-performance: {sid}: missing {missing}, unexpected {extra}")
        site_of[f"performance/summary_{sid}.md"] = f"performance/{sid}/index.md"
        site_of[f"performance/method_{sid}.md"] = f"performance/{sid}/method.md"
        for cid in sorted(pages):
            site_of[f"{cid}/perf_{sid}.md"] = f"performance/{sid}/{cid}.md"

    def rewrite(text, src_rel, dst_rel):
        def repl(match):
            target = match.group(1)
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                return match.group(0)
            path, _, fragment = target.partition("#")
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(src_rel), path))
            if resolved not in site_of:
                return match.group(0)
            relative = posixpath.relpath(site_of[resolved], posixpath.dirname(dst_rel))
            return f"]({relative}{'#' + fragment if fragment else ''})"
        return LINK_RE.sub(repl, text)

    def decorate_summary(text, sid):
        """Add site-native report links, PDF badges and system navigation."""
        def row(match):
            cid, detail, algorithm, instance, after = match.groups()
            report = f"../../reports/{cid}.md"
            identifier = f"[`{cid}`]({report})"
            algorithm = f"[{algorithm}]({report})"
            instance_match = re.fullmatch(r"\s*(`[^`]+`)(.*)", instance)
            if instance_match:
                instance = f"[{instance_match.group(1)}]({detail}){instance_match.group(2)}"
            badge = (f'<a class="pdf-link" href="{HARNESS_RAW}/{cid}/{cid}-spec.pdf" '
                     f'title="Open the {cid} specification PDF">PDF</a>')
            return f"| {identifier} | {algorithm} {badge} | {instance.strip()}{after}"

        choices = []
        for system in systems:
            other = system["ID"]
            choices.append(f"<strong>{other}</strong>" if other == sid else
                           f'<a href="../{other}/index.md">{other}</a>')
        selector = (f'<p class="crumb"><a href="../index.md">Performance measurements</a> › '
                    f'system: {" · ".join(choices)}</p>\n\n')
        text = SUMMARY_ROW_RE.sub(row, text)
        links = " · ".join(
            f"[{target}-bit](ranking-{target}.md)" for target in ORDERED_TARGETS)
        ordered = ("\n\n## Ordered measurements\n\n"
                   f"{links}\n\n"
                   "Compare candidates at a common claimed security target. "
                   "Each table orders the measured metrics and summarizes their "
                   "mean ordinal position; see the individual performance reports "
                   "for measurement details and caveats.")
        first_summary = text.find("\n## Digital signatures")
        if first_summary < 0:
            sys.exit(f"sync-performance: {sid}: first summary heading not found")
        text = text[:first_summary] + ordered + "\n" + text[first_summary:]
        return selector + text

    def decorate_detail(text, sid, cid):
        """Move the navigation line above the H1 as a site breadcrumb and add
        reciprocal system links. Runs after link rewriting, so hrefs are
        already site-relative."""
        lines = text.splitlines()
        h1 = next((i for i, line in enumerate(lines) if line.startswith("# ")), None)
        nav = next((i for i, line in enumerate(lines)
                    if line.startswith(f"[Performance {sid}]")), None)
        if h1 is None or nav is None or nav < h1:
            sys.exit(f"sync-performance: {sid}/{cid}: navigation line not found")
        choices = []
        for system in systems:
            other = system["ID"]
            choices.append(f"<strong>{other}</strong>" if other == sid else
                           f'<a href="../{other}/{cid}.md">{other}</a>')
        crumb = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', lines[nav])
        crumb = re.sub(r"`([^`]+)`", r"<code>\1</code>", crumb)
        crumb = f'<p class="crumb">{crumb} · system: {" · ".join(choices)}</p>'
        del lines[nav]
        if nav < len(lines) and not lines[nav].strip() and not lines[nav - 1].strip():
            del lines[nav]
        # Cross-link the security evaluation from the basic-information list.
        info = next((i for i, line in enumerate(lines)
                     if line.startswith("## 1. Basic information")), None)
        if info is None:
            sys.exit(f"sync-performance: {sid}/{cid}: basic-information section not found")
        end = info + 1
        while end < len(lines) and not lines[end].startswith("- "):
            end += 1
        while end < len(lines) and lines[end].startswith("- "):
            end += 1
        lines.insert(end, f"- Security evaluation: [{cid} report](../../reports/{cid}.md)")
        lines[h1:h1] = [crumb, ""]
        return "\n".join(lines) + ("\n" if text.endswith("\n") else "")

    shutil.rmtree(DEST, ignore_errors=True)
    for src_rel, dst_rel in site_of.items():
        text = (src / src_rel).read_text(encoding="utf-8")
        match = re.fullmatch(r"performance/([^/]+)/index\.md", dst_rel)
        if match:
            text = decorate_summary(text, match.group(1))
        text = rewrite(text, src_rel, dst_rel)
        match = re.fullmatch(r"performance/([^/]+)/((?:sign|kem|kex|hash)-\d\d)\.md", dst_rel)
        if match:
            text = decorate_detail(text, match.group(1), match.group(2))
        out = ROOT / "content" / dst_rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(f"<!-- synchronized from harness: {src_rel} -->\n" + text,
                       encoding="utf-8")

    index = ["# Performance", "",
             "Independent cycle-count measurements of the NGCC Round 1 candidates. "
             "Each system summary reports ICCS-facing parameter sets, primitive operations, and the public-key schemes' share spent in "
             "ICCS placeholder hash functions, and hash timings relative to the ICCS placeholder `pseudoXOF` "
             "with the same message length and output width, itself timed alongside the ICCS helpers. Per-candidate pages retain every measured implementation, including non-ICCS variants omitted from the aggregate table.", "",
             "| system | architecture | machine |", "|---|---|---|"]
    for row in systems:
        index.append(f"| [{row['ID']}]({row['ID']}/index.md) | {row['Arch']} | {row['Description']} |")
    index += ["", "The [symmetric cryptography survey](symmetric-survey.md) records how each "
              "public-key submission implements hashing and randomness. Per-candidate pages include "
              "the measurement method, KAT status, sizes, memory proxies and raw-evidence index.", ""]
    (DEST / "index.md").write_text("\n".join(index), encoding="utf-8")

    # The ordered-measurement pages are site views assembled from the benchmark
    # evidence, security-target metadata and synchronized report inventory.
    for row in systems:
        sid = row["ID"]
        subprocess.run(
            [sys.executable, str(ROOT / "tools" / "rank_performance.py"), str(src),
             "--system", sid, "--output-dir", str(DEST / sid)],
            check=True)
    print(f"sync-performance: {len(site_of) + 1} pages for {len(systems)} system(s), "
          f"{len(candidate_ids)} candidates -> {DEST.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
