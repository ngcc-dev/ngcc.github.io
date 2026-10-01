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

## kex-04-2: DKEX ignores input lengths before fixed-size reads

Severity: Low
Status: Confirmed
Layer: Implementation
Affected: DKEX-128, -256, and -512 x86 and AArch64 KEX APIs, plus the Cortex-M4 KEM wrappers; runtime witness on reference DKEX-128
Discovery: Trivial
Exploitation: Malformed-message out-of-bounds read and process termination; no disclosure demonstrated
Credit: DKEM / DKEX / ADKEX team
Date: 2026-10-01
Original source: [Team's PKC Forum response](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/USUZ2CPOFPWB3JST6BFM4XLGDHGY7URA/)

The DKEX KEX wrappers discard the declared key, state, and message lengths before parsing fixed-size protocol objects (`KEX_AlgorithmInstance.c:71–171`). A truncated pass-1 message can therefore be read beyond its allocation while producing pass 2. The team confirms that the pattern affected the submitted DKEX KEX APIs. The Cortex-M4 package has no KEX API, but its `KEM_AlgorithmInstance.c` wrappers contain the same missing checks and were included in the team's repair.

The local DKEX-128 witness gives pass 2 a one-byte allocation and a declared length of one. AddressSanitizer catches the resulting fixed-size read. No returned disclosure, write, or control-flow effect is demonstrated, so the finding is Low.

### Proposed fixes

The team's [fix commit](https://github.com/dkemdkex/dkem-dkex/commit/c6c2faa) proposes exact checks for every fixed-size input and minimum checks for state buffers before any read or randomness draw. This section records the proposal without evaluating it.

### Reproducing

```sh
make -C kex-04 reproduce-truncated
```
