#!/usr/bin/env python3
"""Render content/ into docs/, the folder GitHub Pages serves.

    python3 tools/build.py          build the site
    python3 tools/build.py --clean  remove generated output only

Every content/**/*.md becomes docs/**/*.html. A page's title is its first H1
(or one derived from its path). Placeholders of the form <!-- table:NAME -->
are expanded before Markdown conversion, where NAME is one of
summary | sign | kem | kex | hash | all, and <!-- reports --> expands to the
issue list built from content/reports/<id>.md. A report is a "Field: value"
header block followed by one "## " section per issue (a "## Reproduc…"
section is a procedure, not an issue, and gets a link to the harness repo). All links are relative, so the site works at any base URL.
"""
import csv
import datetime
import hashlib
import html
import posixpath
import re
import shutil
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parent.parent
CONTENT, DOCS, ASSETS = ROOT / "content", ROOT / "docs", ROOT / "assets"
KEEP = {"CNAME", ".nojekyll"}          # never removed from docs/
SITE = "ngcc.dev"
HARNESS = "https://github.com/ngcc-dev/ngcc-harness"
HARNESS_RAW = "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@main"
MAINTAINER = "markku-juhani.saarinen@tuni.fi"
UPDATED_UTC = datetime.datetime.now(datetime.UTC).replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S UTC")
CATS = [("sign", "Signatures"), ("kem", "KEMs"), ("kex", "Key exchange"), ("hash", "Hash functions")]

NAV = [("Home", "index.html"), ("Reports", "reports/index.html"), ("Constant-time review", "constant-time/index.html"), ("Candidates", "candidates/index.html"),
       ("KAT results", "results.html"), ("Security survey", "security-survey.html"),
       ("Attack matrix", "attack-matrix.html"), ("Audit", "audit.html")]

SEVERITIES = ["critical", "high", "medium", "low", "info"]   # index order = sort order
# Status records how far the individual finding has been substantiated.
STATUSES = ["confirmed", "probable", "lead", "proof gap", "withdrawn"]

STATUS_CLASS = {
    "PASS": "ok", "FINDING": "bad", "MISMATCH": "bad", "CRYPTOFAIL": "bad", "OVERFLOW": "bad",
    "CRASH": "bad", "TIMEOUT": "warn", "ERROR": "warn", "NOKAT": "warn", "SKIP": "muted",
    "confirmed": "bad", "probable": "warn", "not_found": "ok", "ruled_out_by_design": "ok",
    "not_tested": "muted", "not_applicable": "muted", "inconclusive": "warn",
}

def _css_version():
    p = ASSETS / "style.css"
    return hashlib.sha256(p.read_bytes()).hexdigest()[:8] if p.is_file() else "0"


CSS_VER = _css_version()

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{head_title}</title>
<link rel="stylesheet" href="{prefix}assets/style.css?v={css_ver}">
</head>
<body>
<header class="site-header">
<a class="brand" href="{prefix}index.html">{site}</a>
<nav>{nav}</nav>
</header>
<main>
{body}
</main>
<footer class="site-footer">
<p>{updated_line}Maintained by: <a href="mailto:{maintainer}">{maintainer}</a></p>
<p>Submissions are welcome via <a href="{harness}/issues">GitHub issues</a>.</p>
</footer>
</body>
</html>
"""


def read_csv(name, delim=";"):
    p = CONTENT / "data" / name
    if not p.is_file():
        return []
    with open(p, encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter=delim))


def load_candidates():
    """id -> {cat, no, algorithm, submitters, page, zip, forum, kat_pass, kat_total, statuses}"""
    cands = {}
    for cat, _ in CATS:
        for row in read_csv(f"{cat}.csv"):
            cid = f"{cat}-{int(row['No']):02d}"
            cands[cid] = {"id": cid, "cat": cat, "no": int(row["No"]), "algorithm": row["Algorithm"],
                          "submitters": row.get("Submitters", ""), "page": "", "zip": "", "forum": "",
                          "kat_pass": 0, "kat_total": 0, "statuses": []}
    for row in read_csv("downloads.csv"):
        c = cands.setdefault(row["ID"], {"id": row["ID"], "cat": row["Category"], "no": int(row["No"]),
                                         "algorithm": row["Algorithm"], "submitters": "", "kat_pass": 0,
                                         "kat_total": 0, "statuses": []})
        c.update(page=row.get("PageURL", ""), zip=row.get("DownloadURL", ""), forum=row.get("ForumThread", ""))
    for row in read_csv("families.csv"):
        if row.get("ID") in cands:
            cands[row["ID"]]["family"] = row.get("Family", "")
    # per-instance statuses from the KAT results table
    res = CONTENT / "results.md"
    if res.is_file():
        cur = None
        for line in res.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\|\s*((?:sign|kem|kex|hash)-\d\d)?\s*\|[^|]*\|[^|]*\|[^|]*\|\s*(\S+)", line)
            if not m:
                continue
            cur = m.group(1) or cur
            if cur in cands:
                st = m.group(2)
                cands[cur]["statuses"].append(st)
                cands[cur]["kat_total"] += 1
                cands[cur]["kat_pass"] += st == "PASS"
    return cands


def candidate_pages(cid):
    d = CONTENT / "candidates" / cid
    out = []
    for name, label in (("index.md", "findings"), ("report.md", "report"), ("pseudocode.md", "pseudocode")):
        if (d / name).is_file():
            out.append((label, f"candidates/{cid}/{name[:-3]}.html"))
    if (CONTENT / "reports" / f"{cid}.md").is_file():
        out.append(("report", f"reports/{cid}.html"))
    if (CONTENT / "constant-time" / f"{cid}.md").is_file():
        out.append(("CT review", f"constant-time/{cid}.html"))
    return out


def kat_cell(c):
    if not c["kat_total"]:
        return "<td class=\"st muted\">—</td>"
    cls = "ok" if c["kat_pass"] == c["kat_total"] else ("bad" if c["kat_pass"] == 0 else "warn")
    return f"<td class=\"st {cls}\">{c['kat_pass']}/{c['kat_total']} PASS</td>"


def table_html(cands, cat, prefix):
    rows = sorted((c for c in cands.values() if c["cat"] == cat), key=lambda c: c["no"])
    h = ["<table class=\"cands\">",
         "<thead><tr><th>id</th><th>algorithm</th><th>submitters</th><th>KAT</th><th>pages</th><th>NICCS</th></tr></thead><tbody>"]
    for c in rows:
        pages = " · ".join(f"<a href=\"{prefix}{href}\">{lab}</a>" for lab, href in candidate_pages(c["id"]))
        ext = " · ".join(f"<a href=\"{html.escape(c[k])}\">{lab}</a>" for k, lab in (("page", "page"), ("zip", "zip"), ("forum", "forum")) if c.get(k))
        h.append(f"<tr><td><code>{c['id']}</code></td><td>{html.escape(c['algorithm'])}</td>"
                 f"<td class=\"submitters\">{html.escape(c['submitters'])}</td>{kat_cell(c)}"
                 f"<td class=\"links\">{pages or '—'}</td><td class=\"links\">{ext or '—'}</td></tr>")
    h.append("</tbody></table>")
    return "\n".join(h)


def summary_html(cands, prefix):
    h = ["<table class=\"summary\"><thead><tr><th>category</th><th>candidates</th><th>instances</th><th>PASS</th><th>not PASS</th></tr></thead><tbody>"]
    tot = [0, 0, 0]
    for cat, label in CATS:
        cs = [c for c in cands.values() if c["cat"] == cat]
        n, p = sum(c["kat_total"] for c in cs), sum(c["kat_pass"] for c in cs)
        tot[0] += len(cs); tot[1] += n; tot[2] += p
        h.append(f"<tr><td><a href=\"{prefix}candidates/index.html#{cat}\">{label}</a></td><td>{len(cs)}</td><td>{n}</td><td>{p}</td><td>{n - p}</td></tr>")
    h.append(f"<tr class=\"total\"><td>total</td><td>{tot[0]}</td><td>{tot[1]}</td><td>{tot[2]}</td><td>{tot[1] - tot[2]}</td></tr>")
    h.append("</tbody></table>")
    return "\n".join(h)


REPORT_ID_RE = re.compile(r"^(sign|kem|kex|hash)-\d\d$")
ISSUE_ID_RE = re.compile(r"^((?:sign|kem|kex|hash)-\d\d-([1-9]\d*)):\s+(.+)$")
ISSUE_FIELDS = ("Severity", "Status", "Layer", "Affected", "Discovery", "Exploitation", "Credit", "Date")


def parse_report(text):
    """Split a report into (meta dict, body markdown, [issue headings])."""
    lines = text.splitlines()
    i = 0
    while i < len(lines) and (not lines[i].strip() or lines[i].startswith("<!--")):
        i += 1
    meta = {}
    while i < len(lines):
        m = re.match(r"^([A-Z][A-Za-z -]*):\s+(.*\S)\s*$", lines[i])
        if not m:
            break
        meta[m.group(1)] = m.group(2)
        i += 1
    body = "\n".join(lines[i:])
    issues = [h.strip() for h in re.findall(r"^##\s+(.+?)\s*$", body, re.M)
              if not h.strip().lower().startswith("reproduc")]
    return meta, body, issues


def load_reports():
    """Load candidate metadata and independently headed vulnerability records."""
    from markdown.extensions.toc import slugify
    reports = {}
    seen_issues = set()
    rdir = CONTENT / "reports"
    if not rdir.is_dir():
        return reports
    for p in sorted(rdir.glob("*.md")):
        if not REPORT_ID_RE.match(p.stem):
            continue
        meta, body, issues = parse_report(p.read_text(encoding="utf-8"))
        unexpected = set(meta) - {"Candidate", "Family", "Archive"}
        if unexpected:
            raise ValueError(f"report-level issue metadata in {p.name}: {', '.join(sorted(unexpected))}")
        body_lines = body.splitlines()
        heading_lines = {line[3:].strip(): i for i, line in enumerate(body_lines) if line.startswith("## ")}
        parsed_issues = []
        numbers = []
        for heading in issues:
            match = ISSUE_ID_RE.fullmatch(heading)
            if not match or not match.group(1).startswith(p.stem + "-"):
                raise ValueError(f"invalid issue heading in {p.name}: {heading}")
            issue_id, number, title = match.group(1), int(match.group(2)), match.group(3)
            if issue_id in seen_issues:
                raise ValueError(f"duplicate report ID: {issue_id}")
            at = heading_lines[heading] + 1
            if at >= len(body_lines) or body_lines[at].strip():
                raise ValueError(f"missing blank line after {issue_id}")
            issue_meta = {}
            for offset, field in enumerate(ISSUE_FIELDS, 1):
                line_at = at + offset
                expected = f"{field}: "
                if line_at >= len(body_lines) or not body_lines[line_at].startswith(expected):
                    raise ValueError(f"missing {field} metadata for {issue_id}")
                issue_meta[field] = body_lines[line_at][len(expected):].strip()
                if not issue_meta[field]:
                    raise ValueError(f"empty {field} metadata for {issue_id}")
            severity = issue_meta["Severity"].lower()
            status = issue_meta["Status"].lower()
            layer = issue_meta["Layer"].lower()
            if severity not in SEVERITIES:
                raise ValueError(f"invalid severity for {issue_id}: {issue_meta['Severity']}")
            if status not in STATUSES:
                raise ValueError(f"invalid status for {issue_id}: {issue_meta['Status']}")
            if layer not in {"design", "implementation", "evaluation"}:
                raise ValueError(f"invalid layer for {issue_id}: {issue_meta['Layer']}")
            if status == "withdrawn" and severity != "info":
                raise ValueError(f"withdrawn issue must have Info severity: {issue_id}")
            seen_issues.add(issue_id)
            numbers.append(number)
            parsed_issues.append({"id": issue_id, "title": title,
                                  "anchor": slugify(heading, "-"), "severity": severity,
                                  "status": status, "layer": layer, "meta": issue_meta})
        if numbers != list(range(1, len(numbers) + 1)):
            raise ValueError(f"non-sequential report IDs in {p.name}: {numbers}")
        reports[p.stem] = {"cid": p.stem, "meta": meta, "body": body, "issues": parsed_issues}
    return reports


def sev_badge(sev, layer=""):
    label = sev.capitalize() + (f" / {layer}" if layer else "")
    return f'<span class="sev sev-{sev}">{html.escape(label)}</span>'


def status_badge(status):
    css = status.replace(" ", "-")
    return f'<span class="issue-status status-{css}">{html.escape(status.capitalize())}</span>'


def id_cell(c):
    return f'<td class="report-id"><code>{c["id"]}</code></td>'


def pdf_link(c):
    cid = c["id"]
    href = f"{HARNESS_RAW}/{cid}/{cid}-spec.pdf"
    return f'<a class="pdf-link" href="{href}" title="Open the {cid} specification PDF">PDF</a>'


def recent_updates_html(reports, prefix):
    """One linked line per UTC publication date, newest first."""
    by_date = {}
    by_layer = {"implementation": 0, "design": 0}
    withdrawn = 0
    for report in reports.values():
        for issue in report["issues"]:
            if issue["status"] == "withdrawn":
                withdrawn += 1
                continue
            date = issue["meta"]["Date"]
            try:
                datetime.date.fromisoformat(date)
            except ValueError as error:
                raise ValueError(f'invalid Date for {issue["id"]}: {date}') from error
            by_date.setdefault(date, []).append((issue["id"], report["cid"], issue["anchor"]))
            by_layer[issue["layer"]] += 1

    lines = ['<h2 id="recent-additions">Recent additions</h2>']
    for date in sorted(by_date, reverse=True):
        links = []
        for issue_id, cid, anchor in sorted(by_date[date]):
            href = f'{prefix}reports/{cid}.html#{anchor}'
            links.append(f'<a href="{href}"><code>{issue_id}</code></a>')
        lines.append(
            f'<p class="recent-update"><time datetime="{date}">{date}</time> '
            f'({len(links)}): {" ".join(links)}</p>'
        )
    total = sum(by_layer.values())
    lines.append(
        f'<p class="recent-total">Total {total}: implementation {by_layer["implementation"]}, '
        f'design {by_layer["design"]}; withdrawn records {withdrawn}.</p>'
    )
    return "\n".join(lines)


def constant_time_html(cands, prefix):
    """Link every scoped candidate review without turning it into a vulnerability row."""
    lines = []
    for cat, label in CATS:
        lines.append(f'<h2 id="{cat}">{label}</h2>')
        lines.append('<p class="audit-links">')
        for c in sorted((item for item in cands.values() if item["cat"] == cat), key=lambda item: item["no"]):
            cid = c["id"]
            if (CONTENT / "constant-time" / f"{cid}.md").is_file():
                lines.append(f'<a href="{prefix}constant-time/{cid}.html"><code>{cid}</code></a> ')
        lines.append('</p>')
    return "\n".join(lines)


def reports_html(reports, cands, prefix):
    h = []
    for cat, label in CATS:
        h.extend([f'<h2 id="{cat}">{label}</h2>', '<table class="reports">',
                  '<thead><tr><th>identifier</th><th>candidate / spec</th><th>family</th><th>classification</th><th>vulnerability</th></tr></thead><tbody>'])
        for c in sorted((c for c in cands.values() if c["cat"] == cat), key=lambda c: c["no"]):
            cid, r = c["id"], reports.get(c["id"])
            family = (r["meta"].get("Family", "") if r else "") or c.get("family", "")
            if not r:
                name = html.escape(c["algorithm"])
                href = html.escape(c.get("page", ""))
                candidate = f'<a href="{href}">{name}</a>' if href else name
                candidate += f' {pdf_link(c)}'
                h.append(f'<tr>{id_cell(c)}<td>{candidate}</td>'
                         f'<td class="family">{html.escape(family)}</td>'
                         f'<td class="st"><span class="sev sev-none">No report</span></td><td>—</td></tr>')
                continue
            for i, issue in enumerate(r["issues"]):
                issue_href = f'{prefix}reports/{cid}.html#{issue["anchor"]}'
                candidate = (f'<a href="{prefix}reports/{cid}.html">'
                             f'{html.escape(r["meta"].get("Candidate", c["algorithm"]))}</a> {pdf_link(c)}')
                classification = f'<td class="st">{sev_badge(issue["severity"], issue["layer"])}</td>'
                issue_cell = (f'<td>{status_badge(issue["status"])} '
                              f'<a href="{issue_href}"><code>{issue["id"]}</code> '
                              f'{html.escape(issue["title"])}</a></td>')
                if i == 0:
                    span = len(r["issues"])
                    first_cell = id_cell(c).replace('<td ', f'<td rowspan="{span}" ', 1)
                    h.append(f'<tr>{first_cell}'
                             f'<td rowspan="{span}">{candidate}</td>'
                             f'<td rowspan="{span}" class="family">{html.escape(family)}</td>'
                             f'{classification}{issue_cell}</tr>')
                else:
                    h.append(f'<tr>{classification}{issue_cell}</tr>')
        h.append("</tbody></table>")
    return "\n".join(h)


def report_page(r, prefix):
    """Markdown for a report page: H1, metadata table, then the original body."""
    m = r["meta"]
    order = ["Candidate", "Family", "Archive"]
    keys = [k for k in order if k in m] + [k for k in m if k not in order]
    rows = []
    for k in keys:
        v = markdown.markdown(m[k])[3:-4]
        rows.append(f"<tr><th>{html.escape(k)}</th><td>{v}</td></tr>")
    meta_table = '<table class="meta">\n' + "\n".join(rows) + "\n</table>"
    title = f"{m.get('Candidate', r['cid'])} ({r['cid']})"
    crumb = f'<p class="crumb"><a href="{prefix}reports/index.html">Reports</a> › <code>{r["cid"]}</code>'
    if (CONTENT / "constant-time" / f'{r["cid"]}.md').is_file():
        crumb += f' · <a href="{prefix}constant-time/{r["cid"]}.html">Constant-time review</a>'
    crumb += '</p>'
    note = (f"\n\nCommands below run in a checkout of the [ngcc-harness repository]({HARNESS}) "
            f"with the candidate built (see its README).")
    body = r["body"]
    for issue_number, issue in enumerate(r["issues"]):
        heading = f'## {issue["id"]}: {issue["title"]}'
        heading_class = "issue-heading issue-heading-first" if issue_number == 0 else "issue-heading"
        rendered_heading = (
            f'<h2 class="{heading_class}" id="{html.escape(issue["anchor"])}">'
            f'{html.escape(issue["id"])}: {html.escape(issue["title"])}</h2>'
        )
        source_meta = "\n".join(f'{field}: {issue["meta"][field]}' for field in ISSUE_FIELDS)
        rows = [f'<tr><th>Classification</th><td>{sev_badge(issue["severity"], issue["layer"])}</td></tr>',
                f'<tr><th>Status</th><td>{status_badge(issue["status"])}</td></tr>']
        for field in ISSUE_FIELDS[3:]:
            value = markdown.markdown(issue["meta"][field])[3:-4]
            rows.append(f'<tr><th>{html.escape(field)}</th><td>{value}</td></tr>')
        issue_table = '<table class="meta issue-meta">\n' + "\n".join(rows) + "\n</table>"
        source = f"{heading}\n\n{source_meta}"
        if source not in body:
            raise ValueError(f"could not render metadata for {issue['id']}")
        body = body.replace(source, f"{rendered_heading}\n\n{issue_table}", 1)
    body = re.sub(r"^(###[ \t]+Reproduc\w*[ \t]*)$", lambda m: m.group(1) + note, body, flags=re.M)
    return f"{crumb}\n\n# {title}\n\n{meta_table}\n\n{body}", title


def expand_placeholders(text, cands, prefix, reports):
    text = re.sub(r"<!--\s*recent-additions\s*-->",
                  lambda m: recent_updates_html(reports, prefix), text)
    text = re.sub(r"<!--\s*reports\s*-->", lambda m: reports_html(reports, cands, prefix), text)
    text = re.sub(r"<!--\s*constant-time\s*-->", lambda m: constant_time_html(cands, prefix), text)

    def repl(m):
        name = m.group(1)
        if name == "summary":
            return summary_html(cands, prefix)
        if name == "all":
            return "\n".join(f"<h2 id=\"{cat}\">{label}</h2>\n{table_html(cands, cat, prefix)}" for cat, label in CATS)
        if name in dict(CATS):
            return table_html(cands, name, prefix)
        return m.group(0)
    return re.sub(r"<!--\s*table:(\w+)\s*-->", repl, text)


def status_classes(body):
    def repl(m):
        attrs, code_open, token, code_close = m.group(1), m.group(2) or "", m.group(3), m.group(4) or ""
        cls = STATUS_CLASS[token]
        attrs = re.sub(r'\sclass="([^"]*)"', lambda c: f' class="{c.group(1)} st {cls}"', attrs) if 'class="' in attrs else f'{attrs} class="st {cls}"'
        return f"<td{attrs}>{code_open}{token}{code_close}"
    tokens = "|".join(re.escape(t) for t in STATUS_CLASS)
    return re.sub(rf"<td([^>]*)>(<code>)?({tokens})(</code>)?(?=[\s<]|$)", repl, body)


def md_links_to_html(body):
    def repl(m):
        href = m.group(1)
        if re.match(r"^[a-z][a-z0-9+.-]*:", href) or href.startswith("#"):
            return m.group(0)
        path, _, frag = href.partition("#")
        if path.endswith(".md"):
            path = path[:-3] + ".html"
        return f'href="{path}{"#" + frag if frag else ""}"'
    return re.sub(r'href="([^"]*)"', repl, body)


def page_title(text, rel):
    m = re.search(r"^#\s+(.+?)\s*$", text, re.M)
    if m:
        return re.sub(r"[*`_]", "", m.group(1))
    parts = rel.with_suffix("").parts
    if len(parts) >= 3 and parts[0] == "candidates":
        return f"{parts[1]} {parts[2]}"
    return rel.stem.replace("-", " ")


def render(rel, cands, reports):
    text = (CONTENT / rel).read_text(encoding="utf-8")
    depth = len(rel.parts) - 1
    prefix = "../" * depth
    title = page_title(text, rel)
    if rel.parts[0] == "reports" and rel.stem in reports:
        text, title = report_page(reports[rel.stem], prefix)
    if rel.parts[0] == "constant-time" and rel.stem in cands:
        cid = rel.stem
        crumb = f'<p class="crumb"><a href="{prefix}constant-time/index.html">Constant-time review</a> › <code>{cid}</code>'
        if cid in reports:
            crumb += f' · <a href="{prefix}reports/{cid}.html">Report</a>'
        text = crumb + '</p>\n\n' + text
    text = expand_placeholders(text, cands, prefix, reports)
    # candidate pages without an H1 get one, plus a breadcrumb back to the index
    if rel.parts[0] == "candidates" and len(rel.parts) == 3:
        cid = rel.parts[1]
        c = cands.get(cid, {})
        crumb = f"<p class=\"crumb\"><a href=\"{prefix}candidates/index.html#{c.get('cat', '')}\">Candidates</a> › <code>{cid}</code>"
        crumb += "".join(f" · <a href=\"{prefix}{href}\">{lab}</a>" for lab, href in candidate_pages(cid) if href != f"candidates/{cid}/{rel.stem}.html")
        crumb += "</p>\n"
        if not re.search(r"^#\s", text, re.M):
            title = f"{cid} {c.get('algorithm', '')} — {rel.stem}".strip()
            text = f"# {title}\n\n{text}"
        text = crumb + text
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "toc", "sane_lists"],
                             extension_configs={"toc": {"permalink": False}})
    body = md_links_to_html(status_classes(body))
    body = re.sub(r"<table\b", '<div class="table-wrap"><table', body).replace("</table>", "</table></div>")
    nav = "".join(f'<a href="{prefix}{href}">{lab}</a>' for lab, href in NAV
                  if (CONTENT / href).with_suffix(".md").is_file())
    out = DOCS / rel.with_suffix(".html")
    out.parent.mkdir(parents=True, exist_ok=True)
    head_title = SITE if title == SITE else f"{title} · {SITE}"
    is_main_page = len(rel.parts) == 1 or (len(rel.parts) == 2 and rel.name == "index.md")
    updated_line = f"Updated {UPDATED_UTC} · " if is_main_page else ""
    out.write_text(TEMPLATE.format(head_title=html.escape(head_title), site=SITE, harness=HARNESS,
                                   css_ver=CSS_VER, prefix=prefix, nav=nav, body=body,
                                   updated_line=updated_line, maintainer=MAINTAINER), encoding="utf-8")


def clean():
    for p in DOCS.iterdir():
        if p.name in KEEP:
            continue
        shutil.rmtree(p) if p.is_dir() else p.unlink()


def main():
    DOCS.mkdir(exist_ok=True)
    clean()
    if "--clean" in sys.argv:
        return
    if ASSETS.is_dir():
        shutil.copytree(ASSETS, DOCS / "assets")
    if (CONTENT / "data").is_dir():
        shutil.copytree(CONTENT / "data", DOCS / "data")
    cands = load_candidates()
    reports = load_reports()
    pages = sorted(p.relative_to(CONTENT) for p in CONTENT.rglob("*.md"))
    for rel in pages:
        render(rel, cands, reports)
    n_issues = sum(len(r["issues"]) for r in reports.values())
    print(f"build: {len(pages)} pages, {len(reports)} reports ({n_issues} issues), {len(cands)} candidates -> {DOCS.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
