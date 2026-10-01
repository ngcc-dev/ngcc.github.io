<!-- synchronized report: sign-20/report.md -->
Candidate: Qing Luan
Family: Code-based (restricted syndrome decoding, MPC-in-the-head)
Archive: [QingLuan.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/QingLuan.zip) (SHA-256: `2eb8f3ed205eb7c7e8b3108a997b59643d1aa5579035b8093b4ddbe051a48007`)

## sign-20-1: Qingluan-128's own quantum accounting falls below the 80-bit target

Severity: Medium
Status: Proof gap
Layer: Design
Affected: Qingluan-128 specification and parameter set
Discovery: Trivial
Exploitation: The specification's halved-exponent rule gives 64.4 and 71.5 quantum-cost bits; no end-to-end quantum gate cost is established
Credit: Sun Shuzhou, with GLM-5.3 assistance
Date: 2026-10-01
Original source: [Sun's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/QMVN4EMKVLFXOLVNGTSR7KAR4J4OKDFE/)

The NGCC [Submission Requirements](https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf) set an 80-bit quantum-security floor for the 128-bit classical tier. Qingluan §3.2.4 instead applies its rule `quantum = classical/2` to a 128.8-bit Fiat–Shamir forgery estimate and a 143-bit key-recovery estimate. This gives cost exponents 64.4 and 71.5 respectively; the latter is a halved ISD exponent, not a count of identical Grover iterations. The specification's own table consequently prints 64-bit binding security next to an `>= 80 bit` target, while describing the shortfall as “NIST category 1” under bounded-depth Grover rather than literal `2^80` work.

This is a contradiction in the claimed parameter accounting, not a demonstrated quantum forgery. The call's 80-bit target cannot be interpreted as a bare Grover-iteration threshold: that convention would assign AES-128 only `2^64` iterations. Reversible SM3, syndrome decoding, memory, depth, and parallelization costs could readily close the reported 8.5–15.6-bit gaps, and no circuit-level estimate is supplied. Under the classification policy this is therefore a Medium proof gap. Changing only the Fiat–Shamir round parameters does not resolve the inconsistency in the specification's own model because the fixed `(n,k)=(127,76)` key-recovery exponent remains 71.5.

The other three parameter sets are not affected by this numerical inconsistency: under the same convention their stated quantum estimates remain slightly above their 128-, 192-, and 256-bit targets.

### Reproducing

```sh
python3 sign-20/reproduce_quantum_accounting.py
```

The witness extracts the relevant statements and numbers from the submitted PDF, recomputes `128.8/2 = 64.4` and `143/2 = 71.5`, and checks that both fall below the specification's own 80-bit row. It does not simulate a quantum circuit or claim an executed attack.
