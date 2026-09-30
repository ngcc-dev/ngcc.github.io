<!-- synchronized report: kex-04/report.md -->
Candidate: DKEX (Ding Key Exchange)
Family: Lattice (mutually authenticated key exchange)
Archive: [DKEX.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DKEX.zip) (SHA-256: `979c22239b4a2fb6732e68029c06659f8a7b582c00ca163e1ec72874b227e117`)

## kex-04-1: DKEX-512 silently derives different keys in honest sessions

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: Submitted DKEX-512 scalar reference implementation
Discovery: Moderate
Exploitation: Honest-session correctness failure; no confidentiality or authentication attack demonstrated
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-09-30
Original source: [DKEM/DKEX/ADKEX team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/NRJXWUW3IRBVMQZEGW3DNPUVK6PW7YLG/)

DKEX-512 shares the 16-bit scalar NTT arithmetic used by DKEM-512 and ADKEX-512. Legitimate lazy butterfly intermediates at `q=7681` can exceed the signed 16-bit range, corrupting the reconciliation value. The specification nevertheless claims a failure probability of about `2^-167` (Table 2 and §3.3).

The team reports 9 mismatches in 20,000 complete DKEX-512 reference sessions. An independent fixed-seed run found an honest three-pass session mismatch at trial 1379 even though every API call reported success. This is a protocol reliability failure, not a demonstrated key-recovery or authentication attack, hence Low.

### Proposed fixes

The team's [fix commit](https://github.com/dkemdkex/dkem-dkex/commit/8e3417a) proposes additional forward-NTT reductions in the scalar, NEON, and Cortex-M4 paths. This section records the proposal without evaluating it.

### Reproducing

```sh
python3 kex-04/reproduce_correctness.py
```

The witness initializes honest long-term keys, runs complete authenticated three-pass sessions through the submitted API, and compares both derived keys.
