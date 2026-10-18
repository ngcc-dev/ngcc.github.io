#!/usr/bin/env python3
"""Validate the generated NIST subsite, source registry, and determinism."""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urldefrag, urlparse

import build

HREF = re.compile(r'(?:href|src)="([^"]*)"')
BANNED_PUBLIC_TEXT = (
    build.PRIVATE_REPO_TOKEN,
    "/home/",
    "/tmp/",
    "/main/nist",
)


class DocumentValidator(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
    RELEVANT = {"href", "src", "id", "class", "datetime", "name", "content"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.ids: set[str] = set()
        self.targets: list[str] = []
        self.errors: list[str] = []
        self.stack: list[str] = []

    def inspect_tag(self, tag: str, attrs: list[tuple[str, str | None]], closed: bool) -> None:
        raw = self.get_starttag_text() or ""
        names: set[str] = set()
        for name, value in attrs:
            if name in names:
                self.errors.append(f"duplicate {name} attribute on <{tag}>")
            names.add(name)
            if name in self.RELEVANT and value is None:
                self.errors.append(f"missing value for {name} attribute on <{tag}>")
            if name in self.RELEVANT and re.search(rf"\b{re.escape(name)}\s*=\s*(?![\"'])", raw, re.I):
                self.errors.append(f"unquoted or malformed {name} attribute on <{tag}>")
            if name == "id" and value is not None:
                if value in self.ids:
                    self.errors.append(f"duplicate id {value!r}")
                self.ids.add(value)
            if name in {"href", "src"} and value is not None:
                self.targets.append(value)
        if not closed and tag not in self.VOID:
            self.stack.append(tag)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.inspect_tag(tag, attrs, False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.inspect_tag(tag, attrs, True)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected closing </{tag}>")
            return
        self.stack.pop()

    def finish(self) -> None:
        pending = self.rawdata
        if pending and re.search(r"<[^>]*(?:href|src|id|class|datetime|name|content)\s*=", pending, re.I):
            self.errors.append("malformed tag or quoted attribute")
        self.close()
        if self.stack:
            self.errors.append("unclosed tags: " + ", ".join(self.stack))


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def contrast_ratio(first: str, second: str) -> float:
    def luminance(value: str) -> float:
        channels = [int(value[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [channel / 12.92 if channel <= 0.04045
                  else ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    a, b = luminance(first), luminance(second)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


def check_badge_contrast() -> int:
    text = build.NIST_STYLESHEET.read_text(encoding="utf-8")
    values = dict(re.findall(r"--(sev-(?:high|critical)-(?:bg|fg)):\s*(#[0-9a-fA-F]{6})", text))
    problems = 0
    for severity in ("high", "critical"):
        background, foreground = values.get(f"sev-{severity}-bg"), values.get(f"sev-{severity}-fg")
        if not background or not foreground:
            print(f"contrast: missing scoped {severity} colors")
            problems += 1
        elif contrast_ratio(background, foreground) < 4.5:
            print(f"contrast: {severity} badge is below WCAG AA 4.5:1")
            problems += 1
    return problems


def check_links(output: Path) -> tuple[int, int]:
    pages = sorted(output.rglob("*.html"))
    validators: dict[Path, DocumentValidator] = {}
    for page in pages:
        validator = DocumentValidator()
        validator.feed(page.read_text(encoding="utf-8"))
        validator.finish()
        validators[page.resolve()] = validator
    ids = {page: validator.ids for page, validator in validators.items()}
    links = problems = 0
    for page in pages:
        text = page.read_text(encoding="utf-8")
        validator = validators[page.resolve()]
        for error in validator.errors:
            print(f"{page.relative_to(output)}: {error}")
            problems += 1
        folded = text.casefold()
        for banned in BANNED_PUBLIC_TEXT:
            if banned in folded:
                print(f"{page.relative_to(output)}: private research reference leaked: {banned}")
                problems += 1
        if re.search(r'<meta\s+name=["\']robots["\'][^>]*\bnoindex\b', text, re.I):
            print(f"{page.relative_to(output)}: public page carries noindex metadata")
            problems += 1
        relative_page = page.relative_to(output)
        is_report = relative_page.parts and relative_page.parts[0] == "reports"
        expected_footer = build.REPORT_FOOTER if is_report else build.DATED_FOOTER
        if text.count(f"<p>{expected_footer}</p>") != 1:
            print(f"{relative_page}: missing or repeated site footer")
            problems += 1
        if is_report and "Updated 2026-10-18 16:38:32 UTC" in text:
            print(f"{relative_page}: finding page carries the site update timestamp")
            problems += 1
        for tag in ("div", "table", "tbody", "thead"):
            if len(re.findall(rf"<{tag}\b", text)) != len(re.findall(rf"</{tag}>", text)):
                print(f"{page.relative_to(output)}: unbalanced <{tag}>")
                problems += 1
        for raw in validator.targets:
            target = html.unescape(raw)
            try:
                build.safe_url(target)
            except ValueError as error:
                print(f"{page.relative_to(output)}: {error}")
                problems += 1
                continue
            parsed = urlparse(target)
            if parsed.scheme or target.startswith("//"):
                if parsed.hostname == "csrc.nist.gov" and parsed.scheme != "https":
                    print(f"{page.relative_to(output)}: insecure NIST URL {target}")
                    problems += 1
                continue
            path, fragment = urldefrag(target)
            path = unquote(path.split("?", 1)[0])
            links += 1
            destination = page.resolve() if not path else (page.parent / path).resolve()
            if not destination.exists():
                # The independent builder shares the parent site's two static assets.
                # They are present in production docs/ and validated by the main checker.
                if destination.name in {"style.css", "mag-glass.png"} and destination.parent.name == "assets" and (build.ASSETS / destination.name).is_file():
                    continue
                print(f"{page.relative_to(output)}: missing {target}")
                problems += 1
            elif fragment and destination.suffix == ".html" and fragment not in ids.get(destination, set()):
                print(f"{page.relative_to(output)}: missing anchor #{fragment} in {path}")
                problems += 1
    return links, problems


def negative_regressions(source: Path, temp: Path, harness_rev: str) -> int:
    problems = 0
    parser_probe = DocumentValidator()
    parser_probe.feed('<div id="duplicate"><a id="duplicate" href=https://example.test>probe</a></div>')
    parser_probe.finish()
    if not any("duplicate id" in error for error in parser_probe.errors) or not any(
            "unquoted" in error for error in parser_probe.errors):
        print("negative: HTML parser did not reject duplicate ids and unquoted attributes")
        problems += 1
    malformed_probe = DocumentValidator()
    malformed_probe.feed('<a href="unterminated>probe')
    malformed_probe.finish()
    if not any("malformed" in error for error in malformed_probe.errors):
        print("negative: HTML parser did not reject a malformed quoted attribute")
        problems += 1
    unsafe_root = temp / "unsafe-root"
    work = unsafe_root / "work"
    work.mkdir(parents=True)
    marker = unsafe_root / "keep.txt"
    marker.write_text("keep\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(Path(build.__file__).resolve()), "--source", str(source),
         "--output", str(work / ".."), "--harness-rev", harness_rev],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if result.returncode == 0 or marker.read_text(encoding="utf-8") != "keep\n":
        print("negative: unsafe OUTPUT=.. was accepted or modified its target")
        problems += 1
    attacker_tmp = temp / "attacker-tmp"
    attacker_tmp.mkdir()
    result = subprocess.run(
        [sys.executable, str(Path(build.__file__).resolve()), "--source", str(source),
         "--output", str(attacker_tmp / "nested" / "nist"), "--harness-rev", harness_rev],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "TMPDIR": str(attacker_tmp)},
    )
    if result.returncode == 0:
        print("negative: TMPDIR widened the destructive output allowlist")
        problems += 1

    victim = temp / "symlink-victim"
    victim.mkdir()
    victim_marker = victim / "keep.txt"
    victim_marker.write_text("keep\n", encoding="utf-8")
    expected = temp / "site" / "docs" / "nist"
    expected.parent.mkdir(parents=True)
    expected.symlink_to(victim, target_is_directory=True)
    try:
        build.validated_output(expected, expected)
    except ValueError:
        pass
    else:
        print("negative: symlinked output was accepted")
        problems += 1
    if victim_marker.read_text(encoding="utf-8") != "keep\n":
        print("negative: symlink-output validation modified its target")
        problems += 1
    expected.unlink()
    expected.mkdir()
    (expected / ".git").mkdir()
    (expected / "CNAME").write_text("example.test\n", encoding="utf-8")
    try:
        build.validated_output(expected, expected)
    except ValueError:
        pass
    else:
        print("negative: protected output containing CNAME was accepted")
        problems += 1
    overlap_root = temp / "overlap"
    overlap_source = overlap_root / "source"
    overlap_source.mkdir(parents=True)
    overlap_cases = (
        (overlap_source, overlap_source, "equal source/output"),
        (overlap_source, overlap_source / "generated", "output inside source"),
        (overlap_source, overlap_root, "source inside output"),
    )
    for overlap_input, overlap_output, label in overlap_cases:
        try:
            build.validate_source_output(overlap_input, overlap_output)
        except ValueError:
            pass
        else:
            print(f"negative: {label} was accepted")
            problems += 1

    for name, content in (
        ("short.csv", "A,B\n1\n"),
        ("extra.csv", "A,B\n1,2,3\n"),
    ):
        malformed_csv = temp / name
        malformed_csv.write_text(content, encoding="utf-8")
        try:
            build.read_csv(malformed_csv)
        except ValueError as error:
            if "expected 2 fields" not in str(error):
                print(f"negative: ragged CSV gave unclear error: {error}")
                problems += 1
        else:
            print(f"negative: ragged CSV was accepted: {name}")
            problems += 1

    for column, expected_message in (
        ("Scope", "report Affected disagrees with registry Scope"),
        ("Exploitation", "report Exploitation disagrees with registry Exploitation"),
    ):
        fixture = temp / f"mismatched-{column.casefold()}"
        shutil.copytree(source, fixture)
        findings_path = fixture / "findings.csv"
        with findings_path.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            fieldnames = reader.fieldnames
            finding_rows = list(reader)
        finding_rows[0][column] += " altered"
        with findings_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(finding_rows)
        try:
            build.load_findings(fixture, build.load_candidates(fixture))
        except ValueError as error:
            if expected_message not in str(error):
                print(f"negative: {column} mismatch gave unclear error: {error}")
                problems += 1
        else:
            print(f"negative: report/{column} metadata mismatch was accepted")
            problems += 1

    cli_site = temp / "cli-site"
    cli_nist = cli_site / "nist"
    cli_nist.mkdir(parents=True)
    shutil.copy2(Path(build.__file__).resolve(), cli_nist / "build.py")
    bad_source = temp / "bad-csv-source"
    bad_source.mkdir()
    (bad_source / "candidates.csv").write_text("A,B\n1\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(cli_nist / "build.py"), "--source", str(bad_source)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if (result.returncode == 0 or "expected 2 fields, found 1" not in result.stdout
            or "Traceback" in result.stdout):
        print("negative: build CLI did not report malformed CSV cleanly")
        problems += 1

    fixture = temp / "malicious-source"
    shutil.copytree(source, fixture)
    candidates = build.load_candidates(fixture)
    findings = build.load_findings(fixture, candidates)
    report = Path(str(findings[0]["report_path"]))
    report.write_text(report.read_text(encoding="utf-8") +
                      "\n[unsafe link](javascript:alert(1))\n", encoding="utf-8")
    rejected_output = temp / "rejected" / "nist"
    try:
        build.build_fresh(fixture, rejected_output, harness_rev)
    except ValueError:
        pass
    else:
        print("negative: unsafe report link was accepted")
        problems += 1

    fixture = temp / "raw-html-source"
    shutil.copytree(source, fixture)
    candidates = build.load_candidates(fixture)
    findings = build.load_findings(fixture, candidates)
    report = Path(str(findings[0]["report_path"]))
    report.write_text(report.read_text(encoding="utf-8") +
                      "\n<script>raw-html-sentinel</script>\n\n"
                      "```sh\nprintf 'fenced-code-sentinel\\n'\n```\n", encoding="utf-8")
    raw_output = temp / "raw-html" / "nist"
    raw_output.parent.mkdir()
    try:
        build.build_fresh(fixture, raw_output, harness_rev)
        raw_error = None
    except (OSError, ValueError) as error:
        raw_error = error
    rendered = raw_output / "reports" / f'{findings[0]["id"]}.html'
    text = rendered.read_text(encoding="utf-8") if rendered.is_file() else ""
    if raw_error or "<script>raw-html-sentinel</script>" in text or "&lt;script&gt;raw-html-sentinel&lt;/script&gt;" not in text:
        print("negative: raw report HTML was not escaped")
        problems += 1
    if ('<pre><code class="language-sh">' not in text or
            "fenced-code-sentinel" not in text or "&lt;pre&gt;" in text):
        print("negative: Markdown fenced code did not render as a code block")
        problems += 1
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=build.DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=build.DEFAULT_OUTPUT)
    parser.add_argument("--harness-rev", default="")
    parser.add_argument("--skip-determinism", action="store_true")
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    problems = check_badge_contrast()
    try:
        candidates = build.load_candidates(source)
        findings = build.load_findings(source, candidates)
        reproducers = build.load_reproducers(source)
        harness = build.public_harness_urls(args.harness_rev)
    except (OSError, ValueError) as error:
        print(f"registry: {error}")
        return 1
    pages = sorted(output.rglob("*.html")) if output.is_dir() else []
    expected = len(findings) + 4
    if len(pages) != expected:
        print(f"pages: expected {expected}, found {len(pages)}")
        problems += 1
    index_path = output / "index.html"
    if index_path.is_file():
        index = index_path.read_text(encoding="utf-8")
        if ('href="on-ramp.html"' not in index
                or "NIST additional digital signature reports" not in index
                or "Official NIST On-Ramp Round 3" not in index):
            print("index: landing page lacks the On-Ramp report collection or official link")
            problems += 1
        if '<table class="reports">' in index:
            print("index: On-Ramp findings table remains on the general landing page")
            problems += 1
        if 'href="../index.html"' in index or '>Security</a>' in index:
            print("index: main-site navigation leaked into independent NIST subsite")
            problems += 1
    else:
        print("pages: missing index.html")
        problems += 1
    on_ramp_path = output / "on-ramp.html"
    if on_ramp_path.is_file():
        on_ramp = on_ramp_path.read_text(encoding="utf-8")
        for scheme, candidate in candidates.items():
            if on_ramp.count(f"<strong>{scheme}</strong>") != 1:
                print(f"on-ramp: {scheme} does not occur exactly once as a candidate")
                problems += 1
            for kind in ("spec", "archive"):
                if candidate[kind] not in on_ramp:
                    print(f"on-ramp: missing official {kind} URL for {scheme}")
                    problems += 1
        for finding in findings:
            affected = build.markdown_inline(str(finding["report_metadata"]["affected"]))
            if f"Affected: {affected}" not in on_ramp:
                print(f"on-ramp: {finding['id']} lacks canonical Affected metadata")
                problems += 1
        if '<h1 id="nist-signature-on-ramp-round-3">NIST Signature On-Ramp (Round 3)</h1>' not in on_ramp:
            print("on-ramp: missing canonical title")
            problems += 1
        if '<table class="reports">' not in on_ramp:
            print("on-ramp: missing findings table")
            problems += 1
    else:
        print("pages: missing on-ramp.html")
        problems += 1
    classification_path = output / "classification.html"
    if classification_path.is_file():
        classification = classification_path.read_text(encoding="utf-8")
        for css_class, label in (
            ("critical", "Critical"), ("high", "High"),
            ("medium", "Medium"), ("low", "Low"), ("info", "Info"),
        ):
            badge = f'<span class="sev sev-{css_class}">{label}</span>'
            if badge not in classification:
                print(f"classification: missing severity badge {label}")
                problems += 1
    else:
        print("pages: missing classification.html")
        problems += 1
    for finding in findings:
        report = output / "reports" / f'{finding["id"]}.html'
        if not report.is_file():
            print(f"pages: missing report {finding['id']}")
            problems += 1
            continue
        rendered = report.read_text(encoding="utf-8")
        if 'href="../on-ramp.html">NIST Signature On-Ramp (Round 3)</a>' not in rendered:
            print(f"{finding['id']}: report breadcrumb does not return to On-Ramp Round 3")
            problems += 1
        if str(finding["id"]) not in rendered or candidates[str(finding["scheme"])]["spec"] not in rendered:
            print(f"{finding['id']}: report lacks stable ID or official specification link")
            problems += 1
        credit_row = f'<tr><th>Credit</th><td>{build.markdown_inline(str(finding["credit"]))}</td></tr>'
        if credit_row not in rendered:
            print(f"{finding['id']}: report lacks the registered attribution")
            problems += 1
        report_metadata = dict(finding["report_metadata"])
        for label, key in (
            ("Affected", "affected"),
            ("Discovery", "discovery"),
            ("Exploitation", "exploitation"),
            ("Remediation", "remediation"),
        ):
            expected_row = (
                f'<tr><th>{label}</th><td>'
                f'{build.markdown_inline(report_metadata[key])}</td></tr>'
            )
            if expected_row not in rendered:
                print(f"{finding['id']}: report page shortens or changes {label} metadata")
                problems += 1
        if re.search(r"<p>\s*(?:<strong>)?Severity:", rendered):
            print(f"{finding['id']}: source metadata is repeated below the report table")
            problems += 1
        reproducer = reproducers[str(finding["id"])]
        if reproducer["script"]:
            expected_command = f'python3 nist/reproduce.py {finding["id"]}'
            if harness["published"]:
                expected_url = f'{harness["blob"]}/{quote_path(reproducer["script"])}'
                if expected_url not in rendered:
                    print(f"{finding['id']}: report lacks pinned public harness reproducer link")
                    problems += 1
            elif f'nist/{reproducer["script"]}' not in rendered:
                print(f"{finding['id']}: report lacks the harness source path")
                problems += 1
            if expected_command not in rendered or build.digest_markup(reproducer["sha256"]) not in rendered:
                print(f"{finding['id']}: report lacks self-contained command or source hash")
                problems += 1
        if "--source" in rendered:
            print(f"{finding['id']}: report exposes an external source-checkout argument")
            problems += 1
        for target in HREF.findall(rendered):
            path = urldefrag(html.unescape(target))[0]
            if not urlparse(path).scheme and path.lower().endswith((".md", ".pdf")):
                print(f"{finding['id']}: unpublished local document link remains: {target}")
                problems += 1
    harness_revision = str(harness["revision"] or "")
    harness_url = re.compile(r"github\.com/ngcc-dev/ngcc-harness/(?:blob|tree)/([^/]+)/nist")
    reproduction_page = output / "reproduction.html"
    if (not reproduction_page.is_file() or
            f'href="{build.HARNESS_REPOSITORY}"' not in reproduction_page.read_text(encoding="utf-8")):
        print("reproduction.html: missing public ngcc-harness repository link")
        problems += 1
    for page in pages:
        page_text = page.read_text(encoding="utf-8")
        if "NIST Round 3" in page_text:
            print(f"{page.relative_to(output)}: ambiguous 'NIST Round 3' wording remains")
            problems += 1
        for navigation in (
            ">Home</a>", ">Security Findings</a>", ">Classification</a>",
            ">Reproduction</a>", ">Official NIST On-Ramp Round 3</a>",
        ):
            if navigation not in page_text:
                print(f"{page.relative_to(output)}: shared NIST navigation lacks {navigation}")
                problems += 1
        if not harness["published"] and re.search(
                re.escape(build.HARNESS_REPOSITORY) + r"/(?:blob|tree)/", page_text):
            print(f"{page.relative_to(output)}: unpinned harness file URL is live")
            problems += 1
        for revision in harness_url.findall(page_text):
            if revision != harness_revision:
                print(f"{page.relative_to(output)}: mixed public harness revision {revision}")
                problems += 1
    links, link_problems = check_links(output)
    problems += link_problems

    deterministic = "skipped"
    with tempfile.TemporaryDirectory(prefix="ngcc-nist-check-") as temp:
        fresh = Path(temp) / "fresh" / "nist"
        try:
            build.build_fresh(source, fresh, args.harness_rev)
        except (OSError, ValueError) as error:
            print(error)
            print("freshness: rebuild failed")
            return 1
        if not output.is_dir() or tree_digest(output) != tree_digest(fresh):
            print("freshness: requested output differs from a clean build")
            problems += 1
        if not args.skip_determinism:
            second = Path(temp) / "second" / "nist"
            try:
                build.build_fresh(source, second, args.harness_rev)
            except (OSError, ValueError) as error:
                print(error)
                print("determinism: second rebuild failed")
                return 1
            deterministic = "yes" if tree_digest(fresh) == tree_digest(second) else "NO"
            if deterministic == "NO":
                print("determinism: two clean builds differ")
                problems += 1
        problems += negative_regressions(source, Path(temp) / "negative", args.harness_rev)
    print(f"nist check: {len(candidates)} candidates, {len(findings)} reports, "
          f"{len(pages)} pages, {links} internal links, deterministic={deterministic}, {problems} problem(s)")
    return 1 if problems else 0


def quote_path(path: str) -> str:
    from urllib.parse import quote
    return quote(path, safe="/")


if __name__ == "__main__":
    raise SystemExit(main())
