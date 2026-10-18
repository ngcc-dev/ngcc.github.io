# NIST additional-signature subsite

This directory independently builds `https://ngcc.dev/nist/`. It is deliberately
absent from the main ngcc.dev navigation while the NIST additional-signature
review is in progress.

The public source registry, report Markdown, classification policy, and
reproduction references live in `ngcc-harness/nist/`. `/nist/` is the general
landing page; the On-Ramp Round 3 candidate and finding index is generated at
`/nist/on-ramp.html`. This directory contains only the page generator and its
checks. From this directory:

```sh
make build                         # ../../ngcc-harness/nist -> ../docs/nist
make check                         # rebuild and validate the subsite
make serve                         # http://localhost:8000/nist/
make build HARNESS_REV=<40-hex>    # link a published harness commit
make build SOURCE=/path/to/nist    # use another registry checkout
make clean                         # remove ../docs/nist only
```

The parent site’s `make build` and `make check` invoke these targets after the
main generator. The subsite generator owns only `docs/nist/`; it does not add a
link to the main index or navigation.

Builds are written to a temporary sibling and replace `docs/nist/` only after
all pages render successfully. The cleaner and builder reject output paths
outside that exact directory. The checker uses a separate non-destructive
fresh-build function for isolated temporary trees. Generated pages are public
and indexable even though the main site does not currently link them.

The reproduction page always links to the `ngcc-dev/ngcc-harness` repository
root. Until `HARNESS_REV` names a 40-character lowercase commit, individual
harness paths elsewhere are rendered as plain text. The generator never emits
branch-based `/main/nist` links. One supplied revision controls every harness
tree and blob URL.

## Input contract

The source directory contains:

- `candidates.csv`, with one row for each of the nine submissions and official
  NIST `SpecURL` and `ArchiveURL` fields;
- `findings.csv`, with the stable finding registry and a nonempty `Credit`
  value for every report;
- `classification-public.md`, defining the public NIST-specific severity and
  evidence labels without repository-maintenance or harvesting instructions;
- report Markdown at the path in each finding’s `Report` field;
- `reproducers.csv` plus its referenced public scripts, with SHA-256 hashes.

The public harness snapshot is the sole publication input. Relative links in
report prose are published only when their target is present in that snapshot;
specification links are replaced with the candidate’s official NIST PDF link.
Maintainers may refresh the snapshot from a local working checkout, but the
generated site never publishes or depends on that checkout's identity or path.
