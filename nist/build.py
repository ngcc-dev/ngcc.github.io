#!/usr/bin/env python3
"""Build the independent ngcc.dev/nist report listing.

The canonical inputs live under ngcc-harness/nist.  This generator intentionally
has no dependency on the main site's candidate numbering or NGCC classification.
It only borrows the shared visual stylesheet and severity badge classes.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import os
import re
import shutil
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, urlparse

import markdown

HERE = Path(__file__).resolve().parent
SITE_ROOT = HERE.parent
DEFAULT_SOURCE = SITE_ROOT.parent / "ngcc-harness" / "nist"
DEFAULT_OUTPUT = SITE_ROOT / "docs" / "nist"
ASSETS = SITE_ROOT / "assets"
NIST_STYLESHEET = HERE / "style.css"
HARNESS_REPOSITORY = "https://github.com/ngcc-dev/ngcc-harness"
NIST_CALL = "https://csrc.nist.gov/Projects/pqc-dig-sig/standardization/call-for-proposals"
NIST_ROUND3 = "https://csrc.nist.gov/Projects/pqc-dig-sig/round-3-additional-signatures"
EXPECTED_SCHEMES = {"FAEST", "HAWK", "MAYO", "MQOM", "QR-UOV", "SDitH", "SNOVA", "SQIsign", "UOV"}
SCHEME_ORDER = ["SQIsign", "HAWK", "MQOM", "SDitH", "MAYO", "QR-UOV", "SNOVA", "UOV", "FAEST"]
SEVERITIES = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Info", "info": "Info"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
STATUSES = {"confirmed", "probable", "lead", "proof gap", "withdrawn"}
LAYERS = {"design", "implementation", "side-channel", "evaluation"}
PRIVATE_REPO_TOKEN = "nist" + "-sig3"
UNPUBLISHED_HARNESS = object()
REPORT_METADATA_LABELS = {
    "severity", "status", "layer", "affected", "discovery", "exploitation",
    "remediation", "credit", "candidate disposition", "date",
}
FAMILIES = {
    "FAEST": "Symmetric-based signatures", "HAWK": "Lattice-based signatures", "MAYO": "Multivariate signatures",
    "MQOM": "MPC-in-the-Head signatures", "QR-UOV": "Multivariate signatures", "SDitH": "MPC-in-the-Head signatures",
    "SNOVA": "Multivariate signatures", "SQIsign": "Isogeny signatures", "UOV": "Multivariate signatures",
}

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="icon" type="image/png" href="{prefix}assets/mag-glass.png">
<link rel="stylesheet" href="{prefix}assets/style.css?v={css_version}">
<link rel="stylesheet" href="{subroot}style.css?v={nist_css_version}">
</head>
<body class="nist-site">
<header class="site-header">
<a class="brand" href="{subroot}index.html"><img class="brand-icon" src="{prefix}assets/mag-glass.png" alt="" width="28" height="28">ngcc.dev / NIST signatures</a>
<nav><a href="{subroot}index.html">Findings</a><a href="{subroot}classification.html">Classification</a><a href="{subroot}reproduction.html">Reproduction</a><a href="{nist_round3}">NIST Round 3</a></nav>
</header>
<main>
{body}
</main>
<footer class="site-footer">
<p>Independent analysis; ratings are not issued or endorsed by NIST. Source and reproduction material: {source_reference}.</p>
</footer>
</body>
</html>
"""


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        sample = stream.read(4096)
        stream.seek(0)
        delimiter = ";" if sample.count(";") > sample.count(",") else ","
        return list(csv.DictReader(stream, delimiter=delimiter))


def get(row: dict[str, str], *names: str, default: str = "") -> str:
    folded = {key.casefold().replace("_", ""): (value or "").strip() for key, value in row.items()}
    for name in names:
        value = folded.get(name.casefold().replace("_", ""))
        if value:
            return value
    return default


def find_input(source: Path, *names: str) -> Path:
    for name in names:
        candidate = source / name
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"none of {', '.join(names)} exists under {source}")


def contained_file(source: Path, relative: str, label: str) -> Path:
    path = source / relative
    try:
        path.resolve().relative_to(source.resolve())
    except ValueError as error:
        raise ValueError(f"{label}: path escapes the public harness snapshot: {relative}") from error
    if not path.is_file():
        raise FileNotFoundError(f"{label}: public file is missing: {path}")
    return path


def public_harness_urls(revision: str | None) -> dict[str, str | bool | None]:
    """Build public URLs only for an explicitly pinned public commit."""
    revision = (revision or "").strip()
    if not revision:
        return {"revision": None, "published": False, "tree": None, "blob": None}
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("HARNESS_REV must be a 40-character lowercase Git hash")
    return {
        "revision": revision,
        "published": True,
        "tree": f"{HARNESS_REPOSITORY}/tree/{revision}/nist",
        "blob": f"{HARNESS_REPOSITORY}/blob/{revision}/nist",
    }


def validated_output(output: Path) -> Path:
    """Confine destructive replacement to docs/nist or an isolated temp tree."""
    resolved = output.resolve()
    default = DEFAULT_OUTPUT.resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    safe_temp = (
        resolved.name == "nist"
        and resolved != temp_root
        and temp_root in resolved.parents
        and resolved.parent != temp_root
    )
    if resolved != default and not safe_temp:
        raise ValueError(f"refusing unsafe output directory: {output}")
    if resolved == Path(resolved.anchor) or resolved.name in {".git", "."}:
        raise ValueError(f"refusing unsafe output directory: {output}")
    return resolved


def official_nist_url(value: str, field: str, scheme: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != "csrc.nist.gov":
        raise ValueError(f"{scheme}: {field} must be an https://csrc.nist.gov/ URL")
    return value


def load_candidates(source: Path) -> dict[str, dict[str, str]]:
    csv_path = source / "candidates.csv"
    if not csv_path.is_file():
        raise FileNotFoundError(f"public candidate registry is missing: {csv_path}")
    rows = read_csv(csv_path)
    candidates: dict[str, dict[str, str]] = {}
    for row in rows:
        scheme = get(row, "Scheme", "Candidate", "Name", "scheme")
        if not scheme or scheme in candidates:
            raise ValueError(f"candidate registry has missing or duplicate scheme: {scheme!r}")
        spec = official_nist_url(get(row, "SpecURL", "SpecificationURL", "spec_url"), "SpecURL", scheme)
        archive = official_nist_url(get(row, "ArchiveURL", "ZipURL", "archive_url"), "ArchiveURL", scheme)
        status = get(row, "CandidateStatus", "Status", "status", default="Round 3 candidate")
        round_no = get(row, "PackageRound", "Round", "round", default="3")
        candidates[scheme] = {
            "scheme": scheme, "family": get(row, "Family", "family", default=FAMILIES.get(scheme, "")),
            "status": status, "round": round_no, "spec": spec, "archive": archive,
            "spec_label": get(row, "SpecLabel", default="PDF"),
            "archive_label": get(row, "ArchiveLabel", default="ZIP"),
        }
        if scheme == "HAWK" and round_no == "2":
            candidates[scheme]["spec_label"] = "Round 2 PDF"
            candidates[scheme]["archive_label"] = "Round 2 ZIP"
    if set(candidates) != EXPECTED_SCHEMES:
        missing = sorted(EXPECTED_SCHEMES - set(candidates))
        extra = sorted(set(candidates) - EXPECTED_SCHEMES)
        raise ValueError(f"candidate registry mismatch; missing={missing}, extra={extra}")
    ordered = [get(row, "Scheme", "Candidate", "Name", "scheme") for row in rows]
    if ordered != SCHEME_ORDER:
        raise ValueError(f"candidate order differs from NIST Round 3 order: {ordered}")
    return candidates


def load_reproducers(source: Path) -> dict[str, dict[str, str]]:
    """Load the public, self-contained harness script registry."""
    path = source / "reproducers.csv"
    if not path.is_file():
        raise FileNotFoundError(f"public reproducer registry is missing: {path}")
    records: dict[str, dict[str, str]] = {}
    for row in read_csv(path):
        finding_id = get(row, "ID")
        script = get(row, "PublicPath", "ScriptPath")
        digest = get(row, "SHA256", "ScriptSHA256").lower()
        if not finding_id or finding_id in records:
            raise ValueError(f"missing or duplicate reproducer ID: {finding_id!r}")
        if bool(script) != bool(digest):
            raise ValueError(f"{finding_id}: reproducer path and SHA-256 must both be present or absent")
        if script:
            script_path = contained_file(source, script, finding_id)
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"{finding_id}: invalid reproducer SHA-256")
            actual = hashlib.sha256(script_path.read_bytes()).hexdigest()
            if actual != digest:
                raise ValueError(f"{finding_id}: reproducer SHA-256 mismatch")
        records[finding_id] = {"script": script, "sha256": digest}
    return records


def resolve_report(source: Path, report: str, scheme: str, finding_id: str) -> Path:
    options = [source / report, source / "reports" / f"{finding_id}.md",
               source / scheme / f"{finding_id}.md"]
    for path in options:
        if path.is_file():
            try:
                path.resolve().relative_to(source.resolve())
            except ValueError as error:
                raise ValueError(f"{finding_id}: report path escapes the public harness snapshot") from error
            return path
    raise FileNotFoundError(f"{finding_id}: report not found (tried {', '.join(map(str, options))})")


def load_findings(source: Path, candidates: dict[str, dict[str, str]]) -> list[dict[str, object]]:
    path = find_input(source, "findings.csv")
    findings: list[dict[str, object]] = []
    seen: set[str] = set()
    by_scheme: dict[str, list[int]] = {scheme: [] for scheme in candidates}
    for row in read_csv(path):
        fid, scheme = get(row, "ID"), get(row, "Scheme", "Candidate")
        match = re.fullmatch(r"(.+)-([1-9][0-9]*)", fid)
        if not match or match.group(1) != scheme or scheme not in candidates or fid in seen:
            raise ValueError(f"invalid, duplicate, or mismatched finding ID: {fid!r} / {scheme!r}")
        severity_raw = get(row, "Severity").casefold()
        status, layer = get(row, "Status").casefold(), get(row, "Layer").casefold()
        if severity_raw not in SEVERITIES:
            raise ValueError(f"{fid}: invalid severity {get(row, 'Severity')!r}")
        if status not in STATUSES:
            raise ValueError(f"{fid}: invalid status {get(row, 'Status')!r}")
        if layer not in LAYERS:
            raise ValueError(f"{fid}: invalid layer {get(row, 'Layer')!r}")
        report_text = get(row, "Report", default=f"reports/{fid}.md")
        report_path = resolve_report(source, report_text, scheme, fid)
        report_source = report_path.read_text(encoding="utf-8")
        first_line = report_source.splitlines()[0] if report_source.splitlines() else ""
        heading = re.fullmatch(rf"#\s+{re.escape(fid)}\s+—\s+([^:]+):.*", first_line)
        if not heading:
            raise ValueError(f"{fid}: report H1 does not begin with the registry ID and severity")
        heading_severity = heading.group(1).strip().casefold()
        if heading_severity not in SEVERITIES or SEVERITIES[heading_severity] != SEVERITIES[severity_raw]:
            raise ValueError(f"{fid}: report H1 severity {heading.group(1)!r} disagrees with registry")
        date = get(row, "Date")
        if not date:
            head = report_source[:2500]
            found = re.search(r"^(?:\*\*)?Date:(?:\*\*)?\s*(\d{4}-\d{2}-\d{2})\s*$", head, re.M)
            date = found.group(1) if found else ""
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise ValueError(f"{fid}: missing or invalid report Date")
        credit = get(row, "Credit")
        if not credit:
            raise ValueError(f"{fid}: missing Credit")
        disposition = ""
        for line in report_source.splitlines()[1:20]:
            disposition_match = re.fullmatch(r"(?:\*\*)?Candidate disposition:(?:\*\*)?\s*(.+)", line)
            if disposition_match:
                disposition = disposition_match.group(1).strip()
                break
        finding = {
            "id": fid, "scheme": scheme, "severity_key": severity_raw,
            "severity": SEVERITIES[severity_raw], "status": status,
            "layer": layer, "title": get(row, "Title"), "date": date,
            "reproducer": get(row, "Reproducer"),
            "verification": get(row, "Verification"),
            "scope": get(row, "Scope", "Affected"),
            "credit": credit,
            "discovery": get(row, "Discovery"),
            "exploitation": get(row, "Exploitation"),
            "remediation": get(row, "Remediation"),
            "disposition": disposition,
            "report_path": report_path, "report_rel": report_path.relative_to(source).as_posix(),
        }
        if not finding["title"]:
            first = report_path.read_text(encoding="utf-8").splitlines()[0]
            finding["title"] = re.sub(r"^#\s+[^—:]+\s*[—:]\s*(?:\w+:\s*)?", "", first).strip()
        seen.add(fid)
        by_scheme[scheme].append(int(match.group(2)))
        findings.append(finding)
    for scheme, numbers in by_scheme.items():
        if numbers and sorted(numbers) != list(range(1, max(numbers) + 1)):
            raise ValueError(f"{scheme}: finding numbers are not sequential: {sorted(numbers)}")
    return sorted(findings, key=lambda row: (SCHEME_ORDER.index(str(row["scheme"])), int(str(row["id"]).rsplit("-", 1)[1])))


def badge(finding: dict[str, object]) -> str:
    sev_key = "info" if finding["severity_key"] == "informational" else str(finding["severity_key"])
    return f'<span class="sev sev-{sev_key}">{html.escape(str(finding["severity"]))}</span>'


def status_badge(status: str) -> str:
    return f'<span class="issue-status status-{html.escape(status.replace(" ", "-"))}">{html.escape(status.capitalize())}</span>'


def digest_markup(digest: str) -> str:
    return '<code class="digest">' + "<wbr>".join(
        html.escape(digest[index:index + 8]) for index in range(0, len(digest), 8)
    ) + "</code>"


def markdown_body(text: str, *, trusted_html: bool = False) -> str:
    engine = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "sane_lists"])
    if not trusted_html:
        # Disable source HTML parsing before conversion. This leaves literal HTML
        # inert while preserving markup produced by Markdown extensions, including
        # fenced code blocks.
        engine.preprocessors.deregister("html_block")
        engine.inlinePatterns.deregister("html")
    body = engine.convert(text)
    return re.sub(r"<table\b", '<div class="table-wrap"><table', body).replace("</table>", "</table></div>")


def strip_report_metadata(text: str) -> str:
    """Remove the report's leading metadata block; the page table renders it."""
    lines = text.splitlines()
    if not lines:
        return text
    index = 1
    while index < len(lines) and not lines[index].strip():
        index += 1
    start = index
    while index < len(lines):
        match = re.fullmatch(r"(?:\*\*)?([^:*]+):(?:\*\*)?\s*(.*)", lines[index])
        if not match or match.group(1).strip().casefold() not in REPORT_METADATA_LABELS:
            break
        index += 1
    if index == start:
        return text
    while index < len(lines) and not lines[index].strip():
        index += 1
    return "\n".join([lines[0], "", *lines[index:]]).rstrip() + "\n"


def markdown_inline(text: str) -> str:
    rendered = markdown_body(text)
    match = re.fullmatch(r"<p>(.*)</p>", rendered, re.S)
    if not match:
        raise ValueError("Credit must be one inline Markdown paragraph")
    parser = LinkRewriter(lambda target: target)
    parser.feed(match.group(1))
    parser.close()
    return parser.result()


def safe_url(value: str) -> str:
    cleaned = "".join(ch for ch in html.unescape(value).strip() if ord(ch) >= 0x20)
    if cleaned.startswith("//"):
        raise ValueError(f"scheme-relative URL is not allowed: {value!r}")
    scheme = urlparse(cleaned).scheme.casefold()
    if scheme and scheme not in {"https", "http", "mailto"}:
        raise ValueError(f"unsafe URL scheme in {value!r}")
    return cleaned


class LinkRewriter(HTMLParser):
    """Rewrite parsed Markdown links without touching code or link syntax."""

    def __init__(self, rewrite: object) -> None:
        super().__init__(convert_charrefs=False)
        self.rewrite = rewrite
        self.parts: list[str] = []
        self.anchor_tags: list[tuple[str, str]] = []

    @staticmethod
    def attributes(attrs: list[tuple[str, str | None]]) -> str:
        return "".join(
            f' {name}="{html.escape(value, quote=True)}"' if value is not None else f" {name}"
            for name, value in attrs
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        output_tag = tag
        clean_attrs: list[tuple[str, str | None]] = []
        for name, value in attrs:
            if name in {"href", "src"} and value is not None:
                value = safe_url(value)
                if tag == "a" and name == "href":
                    value = self.rewrite(value)
                    if value is None or value is UNPUBLISHED_HARNESS:
                        output_tag = "span"
                        clean_attrs.append(("class", "citation-path"))
                        self.anchor_tags.append((output_tag, ""))
                        continue
            clean_attrs.append((name, value))
        if tag == "a" and len(self.anchor_tags) == 0:
            self.anchor_tags.append((output_tag, ""))
        self.parts.append(f"<{output_tag}{self.attributes(clean_attrs)}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name in {"href", "src"} and value is not None:
                safe_url(value)
        self.parts.append(f"<{tag}{self.attributes(attrs)} />")

    def handle_endtag(self, tag: str) -> None:
        output_tag, suffix = self.anchor_tags.pop() if tag == "a" and self.anchor_tags else (tag, "")
        self.parts.append(f"</{output_tag}>")
        self.parts.append(suffix)

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def handle_entityref(self, name: str) -> None:
        self.parts.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.parts.append(f"&#{name};")

    def handle_comment(self, data: str) -> None:
        self.parts.append(html.escape(f"<!--{data}-->"))

    def handle_decl(self, decl: str) -> None:
        self.parts.append(html.escape(f"<!{decl}>"))

    def result(self) -> str:
        return "".join(self.parts)


def classification_badges(text: str) -> str:
    """Give severity names in rendered policy tables the finding-index colors."""
    badges = {
        "Critical": ("critical", "Critical"),
        "High": ("high", "High"),
        "Medium": ("medium", "Medium"),
        "Low": ("low", "Low"),
        "Informational": ("info", "Info"),
    }
    for rating, (css_class, label) in badges.items():
        text = text.replace(
            f"<td>{rating}</td>",
            f'<td><span class="sev sev-{css_class}">{label}</span></td>',
        )
    return text


def render_page(output: Path, relative: Path, title: str, body: str, css_version: str,
                nist_css_version: str, source_reference: str) -> None:
    validator = LinkRewriter(lambda target: target)
    validator.feed(body)
    validator.close()
    body = validator.result()
    depth = len(relative.parts)  # index.html => assets is one level up; reports/x => two
    prefix = "../" * depth
    subroot = "../" * (depth - 1)
    page = TEMPLATE.format(title=html.escape(f"ngcc.dev: {title}"), prefix=prefix, subroot=subroot,
                           css_version=css_version, nist_css_version=nist_css_version,
                           body=body, source_reference=source_reference,
                           nist_round3=NIST_ROUND3)
    target = output / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(page, encoding="utf-8")


def rewrite_report_links(body: str, finding: dict[str, object], candidate: dict[str, str],
                         source: Path, harness_blob: str | None,
                         harness_tree: str | None) -> str:
    """Rewrite links after Markdown parsing, leaving code spans untouched."""
    report_path = Path(str(finding["report_rel"]))

    def replace(target: str) -> str | None:
        if target.startswith("#") or target.startswith("mailto:"):
            return target
        if re.match(r"https?://", target):
            if PRIVATE_REPO_TOKEN in target.casefold():
                return None
            parsed = urlparse(target)
            public = re.fullmatch(
                r"/ngcc-dev/ngcc-harness/(blob|tree)/[^/]+/nist(?:/(.*))?",
                parsed.path,
            )
            if public:
                public_path = public.group(2) or ""
                if public_path.endswith(("methodology.md", "NIST-rules.md", "classification.md", "classification-public.md")):
                    return "../classification.html"
                public_name = Path(public_path).name
                if public_name.endswith(".md") and re.fullmatch(r".+-[1-9][0-9]*\.md", public_name):
                    return f"{quote(Path(public_name).stem)}.html"
                base = harness_blob if public.group(1) == "blob" else harness_tree
                if not base:
                    return UNPUBLISHED_HARNESS
                suffix = public.group(2)
                rewritten = base + (f"/{suffix}" if suffix else "")
                if parsed.query:
                    rewritten += "?" + parsed.query
                if parsed.fragment:
                    rewritten += "#" + parsed.fragment
                return rewritten
            return target
        if target.startswith("/nist/reports/"):
            return Path(target).name
        plain, marker, fragment = target.partition("#")
        decoded = plain.replace("%20", " ")
        if decoded.endswith("-spec.pdf"):
            new = candidate["spec"]
        elif decoded.endswith("methodology.md") or decoded.endswith("NIST-rules.md"):
            new = "../classification.html"
        elif decoded.endswith(".md") and Path(decoded).name.startswith(str(finding["scheme"]) + "-"):
            report_id = Path(decoded).stem
            new = f"{quote(report_id)}.html"
        else:
            resolved_path = source / report_path.parent / decoded
            try:
                resolved = resolved_path.resolve().relative_to(source.resolve())
            except ValueError:
                return None
            if not resolved_path.is_file():
                return None
            if not harness_blob:
                return UNPUBLISHED_HARNESS
            new = f"{harness_blob}/{quote(resolved.as_posix(), safe='/')}"
        if marker:
            new += "#" + fragment
        return new

    parser = LinkRewriter(replace)
    parser.feed(body)
    parser.close()
    return parser.result()


def _build_into(source: Path, output: Path, harness_rev: str | None) -> tuple[int, int]:
    candidates = load_candidates(source)
    findings = load_findings(source, candidates)
    reproducers = load_reproducers(source)
    harness = public_harness_urls(harness_rev)
    published = bool(harness["published"])
    harness_tree = str(harness["tree"]) if published else ""
    harness_blob = str(harness["blob"]) if published else ""
    source_reference = (
        f'<a href="{html.escape(harness_tree)}">ngcc-harness/nist</a>'
        if published else '<code>ngcc-harness/nist</code>'
    )
    harness_markdown = (
        f"[ngcc-harness/nist]({harness_tree})"
        if published else "`ngcc-harness/nist`"
    )
    reproduction_harness_markdown = (
        f"[ngcc-dev/ngcc-harness]({HARNESS_REPOSITORY}) "
        f"([pinned `nist/` tree]({harness_tree}))" if published
        else f"[ngcc-dev/ngcc-harness]({HARNESS_REPOSITORY}) (`nist/`)"
    )
    finding_ids = {str(finding["id"]) for finding in findings}
    if set(reproducers) != finding_ids:
        raise ValueError(
            "reproducer registry IDs differ from findings; "
            f"missing={sorted(finding_ids - set(reproducers))}, "
            f"extra={sorted(set(reproducers) - finding_ids)}"
        )
    output.mkdir(parents=True, exist_ok=False)
    css_version = hashlib.sha256((ASSETS / "style.css").read_bytes()).hexdigest()[:8]
    nist_css_version = hashlib.sha256(NIST_STYLESHEET.read_bytes()).hexdigest()[:8]
    shutil.copy2(NIST_STYLESHEET, output / "style.css")

    grouped = {scheme: [f for f in findings if f["scheme"] == scheme] for scheme in SCHEME_ORDER}
    rows = []
    for scheme in SCHEME_ORDER:
        candidate, records = candidates[scheme], grouped[scheme]
        links = (f'<a class="pdf-link" href="{html.escape(candidate["spec"])}">{html.escape(candidate["spec_label"])}</a> · '
                 f'<a href="{html.escape(candidate["archive"])}">{html.escape(candidate["archive_label"])}</a>')
        status = html.escape(candidate["status"])
        if "withdraw" in candidate["status"].casefold():
            status = (f'<span class="issue-status status-withdrawn">Withdrawn</span><br>'
                      f'<small>NIST package: Round {html.escape(candidate["round"])}</small>')
        if not records:
            rows.append(f'<tr><td><strong>{html.escape(scheme)}</strong></td><td>{html.escape(candidate["family"])}</td>'
                        f'<td>{links}<br><small>{status}</small></td><td><span class="sev sev-none">No finding</span></td><td>—</td></tr>')
            continue
        for index, finding in enumerate(records):
            report_link = f'reports/{quote(str(finding["id"]))}.html'
            finding_cell = (f'{status_badge(str(finding["status"]))} <a href="{report_link}">'
                            f'<code>{html.escape(str(finding["id"]))}</code> {html.escape(str(finding["title"]))}</a>')
            if finding["scope"]:
                finding_cell += f'<br><small>Affected: {html.escape(str(finding["scope"]))}</small>'
            date = (f'<time datetime="{html.escape(str(finding["date"]))}">{html.escape(str(finding["date"]))}</time>'
                    if finding["date"] else "—")
            issue = (f'<td class="severity">{badge(finding)}</td><td class="layer">{html.escape(str(finding["layer"]))}</td>'
                     f'<td class="updated">{date}</td><td>{finding_cell}</td>')
            if index == 0:
                rowspan = len(records)
                rows.append(f'<tr><td rowspan="{rowspan}"><strong>{html.escape(scheme)}</strong></td>'
                            f'<td rowspan="{rowspan}" class="family">{html.escape(candidate["family"])}</td>'
                            f'<td rowspan="{rowspan}">{links}<br><small>{status}</small></td>{issue}</tr>')
            else:
                rows.append(f"<tr>{issue}</tr>")

    active = [f for f in findings if f["status"] != "withdrawn"]
    counts = {label: sum(f["severity"] == label for f in active) for label in ("Critical", "High", "Medium", "Low", "Info")}
    count_text = ", ".join(f"{count} {label}" for label, count in counts.items() if count)
    index_md = f"""# NIST additional digital signatures: independent security reports

This is an independent review of the nine submissions listed by NIST for the
third round of its additional post-quantum signature process. It applies the
[NIST-specific classification policy](classification.html) to the call's
security requirements and each submission's own claims. Ratings are project
assessments, not NIST findings.

The official [NIST call for proposals]({NIST_CALL}) and [Round 3 candidate
page]({NIST_ROUND3}) define the evaluation baseline and candidate set. Each
candidate row links directly to the specification PDF and submission ZIP on
`csrc.nist.gov`. Package rounds and candidate status come from the public
harness registry.

Severity is color-coded: <span class="sev sev-critical">Critical</span>
<span class="sev sev-high">High</span>
<span class="sev sev-medium">Medium</span>
<span class="sev sev-low">Low</span>
<span class="sev sev-info">Info</span>. Evidence status is separate:
<span class="issue-status status-confirmed">Confirmed</span>,
<span class="issue-status status-probable">Probable</span>,
<span class="issue-status status-lead">Lead</span>, and
<span class="issue-status status-proof-gap">Proof gap</span>.

<p class="report-totals">{len(active)} active findings across {sum(bool(v) for v in grouped.values())} candidates: {count_text}.</p>

<table class="reports">
<thead><tr><th>candidate</th><th>family</th><th>NIST files</th><th>severity</th><th>layer</th><th>updated</th><th>finding</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody></table>

“No finding” means only that no numbered report is currently published. It is
not a security endorsement. Reproducers, compact KAT material, source hashes,
and harvesting records are maintained in
{harness_markdown}.
"""
    render_page(output, Path("index.html"), "NIST additional signature reports",
                markdown_body(index_md, trusted_html=True), css_version, nist_css_version,
                source_reference)

    classification_path = find_input(source, "classification-public.md")
    classification = classification_path.read_text(encoding="utf-8")
    classification = re.sub(r"^#\s+.*$", "# NIST additional-signature report classification", classification, count=1, flags=re.M)
    classification_body = classification_badges(markdown_body(classification))
    classification_body = (
        '<p class="crumb"><a href="index.html">NIST signature reports</a> › Classification</p>\n'
        + classification_body
        + markdown_body(f"## Governing NIST documents\n\n- [Call for Proposals]({NIST_CALL})\n"
                        f"- [Round 3 additional signatures]({NIST_ROUND3})\n")
    )
    render_page(output, Path("classification.html"), "NIST report classification",
                classification_body, css_version, nist_css_version, source_reference)

    for finding in findings:
        candidate = candidates[str(finding["scheme"])]
        text = strip_report_metadata(finding["report_path"].read_text(encoding="utf-8"))
        report_body = rewrite_report_links(markdown_body(text), finding, candidate, source,
                                           harness_blob or None, harness_tree or None)
        reproducer = reproducers[str(finding["id"])]
        if reproducer["script"]:
            script = reproducer["script"]
            digest = reproducer["sha256"]
            command = f'<code>python3 nist/reproduce.py {html.escape(str(finding["id"]))}</code>'
            if published:
                reproducer_url = f"{harness_blob}/{quote(script, safe='/')}"
                runner_url = f"{harness_blob}/reproduce.py"
                reproduction_row = (f'<tr><th>Reproduction</th><td><a href="{html.escape(runner_url)}">harness runner</a>: '
                                    f'{command}<br><small>public source: <a href="{html.escape(reproducer_url)}">'
                                    f'<code>nist/{html.escape(script)}</code></a> · '
                                    f'SHA-256 {digest_markup(digest)}</small>')
            else:
                reproduction_row = (f'<tr><th>Reproduction</th><td>harness runner: '
                                    f'{command}<br><small>source: <code>nist/{html.escape(script)}</code> '
                                    f'· SHA-256 {digest_markup(digest)}</small>')
            if finding["verification"]:
                reproduction_row += f'<br><small>{html.escape(str(finding["verification"]))}</small>'
            reproduction_row += "</td></tr>"
        else:
            reproduction_row = '<tr><th>Reproduction</th><td>Primary-source review; no retained executable reproducer.</td></tr>'
        disposition_row = (
            f'<tr><th>Candidate disposition</th><td>{html.escape(str(finding["disposition"]))}</td></tr>'
            if finding["disposition"] else ""
        )
        header = (f'<p class="crumb"><a href="../index.html">NIST signature reports</a> › '
                  f'<code>{html.escape(str(finding["id"]))}</code></p>\n\n'
                  f'<table class="meta issue-meta"><tr><th>Severity</th><td>{badge(finding)}</td></tr>'
                  f'<tr><th>Status</th><td>{status_badge(str(finding["status"]))}</td></tr>'
                  f'<tr><th>Layer</th><td>{html.escape(str(finding["layer"]))}</td></tr>'
                  f'<tr><th>Affected</th><td>{html.escape(str(finding["scope"]))}</td></tr>'
                  f'<tr><th>Discovery</th><td>{html.escape(str(finding["discovery"]))}</td></tr>'
                  f'<tr><th>Exploitation</th><td>{html.escape(str(finding["exploitation"]))}</td></tr>'
                  f'<tr><th>Remediation</th><td>{html.escape(str(finding["remediation"]))}</td></tr>'
                  f'<tr><th>Credit</th><td>{markdown_inline(str(finding["credit"]))}</td></tr>'
                  f'<tr><th>Updated</th><td><time datetime="{html.escape(str(finding["date"]))}">'
                  f'{html.escape(str(finding["date"]))}</time></td></tr>'
                  f'{disposition_row}'
                  f'{reproduction_row}'
                  f'<tr><th>NIST files</th><td><a href="{html.escape(candidate["spec"])}">specification PDF</a> · '
                  f'<a href="{html.escape(candidate["archive"])}">submission ZIP</a></td></tr></table>\n\n')
        render_page(output, Path("reports") / f'{finding["id"]}.html', str(finding["id"]), header + report_body, css_version,
                    nist_css_version, source_reference)

    hashed = []
    inputs = [find_input(source, "candidates.csv"), find_input(source, "findings.csv"),
              find_input(source, "reproducers.csv"), classification_path]
    if (source / "snapshot.json").is_file():
        inputs.append(source / "snapshot.json")
    inputs.extend(Path(str(f["report_path"])) for f in findings)
    inputs.extend(source / row["script"] for row in reproducers.values() if row["script"])
    for path in sorted(set(inputs), key=lambda item: item.relative_to(source).as_posix()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        hashed.append(f'| `{path.relative_to(source).as_posix()}` | {digest_markup(digest)} |')
    reproduction = f"""# Reproducing this NIST report site

The authoritative publication input is {reproduction_harness_markdown}. Its
candidate registry pins official NIST archive and specification hashes without
checking large ZIP files into Git. Report pages link to compact reproducer
scripts where a runtime or mathematical witness exists. The harness fetches
the pinned official NIST submission packages when submitted source is needed;
its published runners do not depend on a separate research repository.

Maintainers may refresh the normalized snapshot from a local working checkout.
That import path is not part of the published data or reproduction interface.

Build the subsite from a checkout of `ngcc.github.io`:

```sh
make -C nist build SOURCE=../../ngcc-harness/nist
make -C nist check SOURCE=../../ngcc-harness/nist
```

The builder does not read the clock or local Git state. Two clean builds from
the same input are byte-identical, and `make check` verifies this property.

## Published input hashes

| input | SHA-256 |
|---|---|
{chr(10).join(hashed)}
"""
    render_page(output, Path("reproduction.html"), "Reproducing the NIST report site",
                markdown_body(reproduction, trusted_html=True), css_version,
                nist_css_version, source_reference)
    return len(candidates), len(findings)


def build(source: Path, output: Path, harness_rev: str | None = None) -> tuple[int, int]:
    """Build beside the destination and replace it only after success."""
    output = validated_output(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.build-", dir=output.parent))
    staging.rmdir()  # _build_into requires a new directory.
    backup: Path | None = None
    try:
        counts = _build_into(source, staging, harness_rev)
        if output.exists():
            if output.is_symlink() or not output.is_dir():
                raise ValueError(f"refusing to replace non-directory output: {output}")
            backup = Path(tempfile.mkdtemp(prefix=f".{output.name}.old-", dir=output.parent))
            backup.rmdir()
            os.replace(output, backup)
        try:
            os.replace(staging, output)
        except Exception:
            if backup is not None and backup.exists() and not output.exists():
                os.replace(backup, output)
            raise
        if backup is not None:
            shutil.rmtree(backup)
        print(f"nist build: 3 index/policy/reproduction pages, {counts[1]} reports, "
              f"{counts[0]} candidates -> {output}")
        return counts
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def clean(output: Path) -> None:
    output = validated_output(output)
    if output.exists():
        if output.is_symlink() or not output.is_dir():
            raise ValueError(f"refusing to clean non-directory output: {output}")
        shutil.rmtree(output)
    print(f"nist clean: removed {output}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--harness-rev", default="",
                        help="published ngcc-harness commit (40 lowercase hex characters)")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if args.clean:
        clean(output)
    else:
        build(source, output, args.harness_rev)


if __name__ == "__main__":
    main()
