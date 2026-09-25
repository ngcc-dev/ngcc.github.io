<!-- synchronized report: sign-23/report.md -->
Candidate: Shuttle
Family: Lattice (Module-LWE/Module-SIS)
Archive: [shuttle.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/shuttle.zip) (SHA-256: `09253fd33c2215098177991db3375cb94e4e4a73a65b019783edabefa5bd8a62`)

## sign-23-1: Reversed transition leaks Shuttle's signing key

Severity: Critical
Status: Confirmed
Layer: Design
Affected: Shuttle-128, -256, and -512 NGCC specification and reference implementations
Discovery: Non-trivial
Exploitation: Equivalent-key recovery and accepted fresh-message forgeries from 175,000/275,000/300,000 valid signatures in independent 128/256/512 tests
Credit: Martin Feussner, with OpenAI Codex (Daybreak Blue) assistance
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/5ao-Ebsa_Ow/m/zwYJk_Q-BAAJ)

Figure 1, Eq. (8), and §4.1.1 define `p_v(y)` as the probability of returning `y−v`, but Algorithm 22 sets its flag on the corresponding interval event and returns `y+flag·v`. All three reference `irs.c` files implement that same sign (`irs.c:382–399`). Reversing the intended transition leaves a secret-dependent covariance in valid responses. The constant first component of Shuttle's signing secret supplies a public anchor for estimating the other secret components. An independent driver recovered an equivalent key using only ordinary signatures and the public key, then produced an accepted fresh-message forgery at every level. The original analysis also reports a corrected-sign control; that control has not been independently rerun. The authors' separate [ePrint 2026/1991](https://eprint.iacr.org/2026/1991) uses the matching `y−v` branch, so this finding concerns the NGCC submission.

### Reproducing

```sh
make -C sign-23 exploit
tools/reproduce.sh sign-23
```

The independent driver parses verified signatures, accumulates challenge-conditioned covariance, checks recovered secret coefficients through the public-key relation and key-generation bounds, and signs a fresh message with the resulting equivalent key. It splits ordinary signing queries over eight independent processes by default; no original secret data enters the estimator or public completion. The [original post](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/5ao-Ebsa_Ow/m/zwYJk_Q-BAAJ) describes the same mechanism.
