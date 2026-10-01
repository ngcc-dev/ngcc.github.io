# ngcc.dev

Source for <https://ngcc.dev>. Pages are Markdown under `content/`, rendered
by `tools/build.py` into `docs/`, which GitHub Pages serves directly (no
Jekyll). Requires Python 3 and the `markdown` package.

    make build      # content/ -> docs/
    make serve      # preview on http://localhost:8000
    make sync REPORT_SOURCE=../ngcc1 PERF_SOURCE=../ngcc-harness
    git commit -a && git push   # deploy

The combined sync updates reports first and performance second, so the ordered
measurement pages always recompute their security badges from the current
reports. The performance sync validates that every registered candidate has a generated
page, copies the harness summaries into `content/performance/`, and rewrites
their internal links. Run `make check` afterward to rebuild and validate the
published `docs/` tree.

`tools/build.py` also gives every official candidate a stable `reports/<id>.html`
page. Candidates without a report source get a generated “No finding” review
page; these pages do not create issue IDs or change the vulnerability totals.

Both `content/` and the rendered `docs/` are committed, so what is pushed is
exactly what is served. Everything in this repository is public, including
its history: commit only material that is ready to be on the site.
