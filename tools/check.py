#!/usr/bin/env python3
"""Verify the rendered site in docs/: internal links, anchors, tag balance.

    python3 tools/check.py                 (check the whole site)
    python3 tools/check.py --ngcc-only     (do not inspect the NIST subsite)

Run before committing; docs/ is what GitHub Pages serves, so a stale or
broken build is visible immediately.
"""
import html
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urldefrag

DOCS = Path(__file__).resolve().parent.parent / "docs"
HREF = re.compile(r'(?:href|src)="([^"]*)"')


def main():
    if "--ngcc-only" in sys.argv:
        pages = sorted(
            p for top in DOCS.iterdir() if top.name != "nist"
            for p in (top.rglob("*.html") if top.is_dir() else [top])
            if p.suffix == ".html"
        )
    else:
        pages = sorted(DOCS.rglob("*.html"))
    if not pages:
        sys.exit("check: docs/ has no pages — run `make build`")
    ids = {p: set(re.findall(r'id="([^"]*)"', p.read_text(encoding="utf-8"))) for p in pages}
    links = problems = 0

    for p in pages:
        text = p.read_text(encoding="utf-8")
        for tag in ("div", "table", "tbody", "thead"):
            if len(re.findall(rf"<{tag}\b", text)) != len(re.findall(rf"</{tag}>", text)):
                print(f"{p.relative_to(DOCS)}: unbalanced <{tag}>")
                problems += 1
        for raw in HREF.findall(text):
            target = html.unescape(raw)                     # &#109;... -> mailto:...
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("//"):
                continue                                    # external / mailto
            path, frag = urldefrag(target)
            path = unquote(path.split("?", 1)[0])            # drop ?v= cache buster
            links += 1
            dest = p if not path else (p.parent / path).resolve()
            if not dest.exists():
                print(f"{p.relative_to(DOCS)}: missing {target}")
                problems += 1
            elif frag and dest.suffix == ".html" and frag not in ids.get(dest, set()):
                print(f"{p.relative_to(DOCS)}: no anchor #{frag} in {path or dest.name}")
                problems += 1

    print(f"check: {len(pages)} pages, {links} internal links, {problems} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
