# Reports

Candidates follow the official type and candidate-number order. Each finding
has a stable `xxx-yy-z` identifier and its own row. Click it for the full report
and reproduction steps.

## Reading the table

- <span class="sev sev-none">No report</span> means no attack report has been
  published here. It does **not** mean the candidate has been found secure.
- Severity is color-coded:
  <span class="sev sev-critical">Critical</span>
  <span class="sev sev-high">High</span>
  <span class="sev sev-medium">Medium</span>
  <span class="sev sev-low">Low</span>
  <span class="sev sev-info">Info</span>.
  Classification also gives scope: **design** concerns the submitted construction
  or specification; **implementation** concerns the submitted code, API, or integration.
- The badge beside each vulnerability gives its evidential status:
  <span class="issue-status status-confirmed">Confirmed</span>,
  <span class="issue-status status-probable">Probable</span> (defect confirmed,
  attack not yet derived), <span class="issue-status status-lead">Lead</span>
  (heuristic, not instantiated), or
  <span class="issue-status status-proof-gap">Proof gap</span> (a proof does not
  support the claim; not itself an attack).
- <span class="issue-status status-withdrawn">Withdrawn</span> preserves an ID
  for an evaluation-only observation that depended on a placeholder primitive;
  it is not counted as an active vulnerability.

Separate [constant-time reviews](../constant-time/index.md) cover all candidates
at source level; a review without a finding is not a security certification.

<!-- recent-additions -->

<!-- reports -->
