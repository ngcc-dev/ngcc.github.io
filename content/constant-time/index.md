# Constant-time source reviews

These 119 notes inspect representative reference paths for branches, variable
work, and memory accesses controlled by secret data. Each note states its
scope and evidence. A note with no finding is a limited review, not a
constant-time certification. A source trace alone does not establish a remote
timing attack or key recovery; see the linked [reports](../reports/index.md)
for finding-specific impact and status.

Some reviews cite submission source files that are not bundled in the compact
[public harness](https://github.com/ngcc-dev/ngcc-harness). To inspect them,
download the official archive with `IDS=<id> ./download.sh`, verify its digest
against `SOURCE_ARCHIVES.md`, and run `./extract.sh <id>` in a harness checkout.

<!-- constant-time -->
