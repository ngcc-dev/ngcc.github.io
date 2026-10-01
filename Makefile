# ngcc.dev static site. GitHub Pages serves docs/ from the main branch.
#
#   make build   render content/*.md -> docs/
#   make serve   preview at http://localhost:8000
#   make check   verify the rendered site (links, anchors, tag balance)
#   make sync REPORT_SOURCE=/path/to/source-checkout
#   make sync-performance PERF_SOURCE=/path/to/harness-checkout
#   make clean   remove generated output (keeps docs/CNAME and docs/.nojekyll)

REPORT_SOURCE ?=
PERF_SOURCE ?= ../ngcc-harness
PORT  ?= 8000

.PHONY: build check serve sync sync-performance clean
build:
	python3 tools/build.py
check: build
	python3 tools/check.py

serve: build
	python3 -m http.server -d docs $(PORT)
sync:
	@test -n "$(REPORT_SOURCE)" || { echo "set REPORT_SOURCE=/path/to/source-checkout" >&2; exit 2; }
	python3 tools/sync.py "$(REPORT_SOURCE)"
	@test -n "$(PERF_SOURCE)" || { echo "set PERF_SOURCE=/path/to/harness-checkout" >&2; exit 2; }
	python3 tools/sync_performance.py "$(PERF_SOURCE)"
sync-performance:
	@test -n "$(PERF_SOURCE)" || { echo "set PERF_SOURCE=/path/to/harness-checkout" >&2; exit 2; }
	python3 tools/sync_performance.py "$(PERF_SOURCE)"
clean:
	python3 tools/build.py --clean
