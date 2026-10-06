<!-- head-title: ngcc.dev: Independent analysis of Chinese Next Generation Commercial Cryptographic (NGCC) algorithms program candidate algorithms -->
# ngcc.dev

Independent analysis of Chinese
[Next Generation Commercial Cryptographic (NGCC) algorithms program](https://www.niccs.org.cn/en/)
candidate algorithms.
This site is not affiliated with NICCS.

- [Security](reports/index.md) — security findings
  ([classification policy](report-classification.md)), each linking to the full
  report and its reproduction steps.
- [Performance](performance/index.md) — cycle counts for ICCS-facing
  parameter sets, placeholder-hash shares, relative hash measurements, and
  detailed pages retaining every measured implementation.
- [Side-Channel](constant-time/index.md) — scoped constant-time source-level notes
  for all 119 candidates, including cases without a finding.
- [Harness](https://github.com/ngcc-dev/ngcc-harness) — the build and test tooling
  the reproductions rely on.
- [“Chinese NGCC Algorithms: The First Week of AI Cryptanalysis”](https://eprint.iacr.org/2026/2266) — IACR Cryptology ePrint Archive, Report 2026/2266.

## Citing

To cite this web site:

```bibtex
@misc{ngccdev,
  author       = {Saarinen, Markku-Juhani O.},
  title        = {{ngcc.dev}: Independent Analysis of the {NGCC} Candidates},
  year         = {2026},
  url          = {https://ngcc.dev/},
  note         = {Accessed <!-- date -->}
}
```

To cite one finding, use its stable `xxx-yy-z` identifier and credit the people
named in that finding's `Credit` field, who are often **not** the maintainer of
this site:

```bibtex
@misc{ngccdev-sign-32-1,
  author       = {Vulnerability Author},
  title        = {{UVW}: Every Signature is Accepted},
  year         = {2026},
  url          = {https://ngcc.dev/reports/sign-32.html},
  note         = {Finding \texttt{sign-32-1}, ngcc.dev. Accessed <!-- date -->}
}
```

The braces around `{ngcc.dev}` and the acronyms stop BibTeX from lowercasing
them. Load `hyperref` or `url` to make the link clickable. For
`biblatex`, use `@online` and give the access date as `urldate`. The original
standard styles (`plain`, `abbrv`, `alpha`, `unsrt`) ignore the `url` field; with
those, either use a URL-aware style such as `splncs04` or `IEEEtran`, or move the
address into `howpublished = {\url{...}}`.

Findings are added and revised continuously, so please cite the date you read a
page rather than the date prefilled above, and quote the finding identifier so
the reference stays resolvable if a title is reworded.
