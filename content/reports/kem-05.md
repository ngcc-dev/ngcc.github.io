<!-- synchronized report: kem-05/report.md -->
Candidate: BIKE-MLThre
Family: Code-based (QC-MDPC)
Archive: [BIKE_MLThre.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BIKE_MLThre.zip) (SHA-256: `3a5d97532003786374b68b39779cff4e4938f593fef9596f171652c6ff593917`)

## kem-05-1: The default library deterministically generates a public secret key

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Default submitted reference-library build, all four parameter sets
Discovery: Trivial
Exploitation: One local key generation; the victim's complete secret key is reproduced
Credit: Zhenyu Xiong and Mingsheng Wang, Institute of Information Engineering, Chinese Academy of Sciences
Date: 2026-09-30
Original source: [Xiong and Wang's PKC Forum post](https://list.niccs.org.cn/archives/list/pkcforum@list.niccs.org.cn/message/AXAPSYKLHJBJHNYCZO57NUKTBTNNCLPV/)

The submitted default `make all` builds `libbike_v2.a` with `-DNIST_RAND=1` and `FromNIST/rng.c` (`Makefile:4–5,24–26,32–46`). That file's global AES-CTR DRBG state starts at zero, but the public library exposes only the KEM API and no library path calls `randombytes_init`. Key generation immediately draws both secret seeds from this state (`kem.c:100–130`). Only the separate KAT wrapper initializes the DRBG (`kat/KEM_AlgorithmInstance.c:18`).

Consequently, the first key pair in every fresh process is fixed and publicly reproducible. For BIKE-MLThre-128 its public key begins `b505bc3a4fd4de9a86991932daad9337bf3343b2ea3697bd11443da3e1388027`, exactly as reported. The same source path is selected for the 192-, 256-, and 512-bit builds. Reproducing the secret key gives immediate decapsulation and violates every claimed security level, hence Critical.

### Reproducing

```sh
python3 kem-05/reproduce_unseeded_drbg.py
```

The witness compiles the archived 128-bit sources with the submitted default flags, compares key generation in two fresh processes, and checks the reported public-key prefix. Initializing the same DRBG with two distinct seeds produces distinct keys as a control.

## kem-05-2: Same-key multi-instance decoding misses BIKE-MLThre-128 and -256 targets

Severity: Critical
Status: Confirmed
Layer: Design
Affected: BIKE-MLThre-128 and BIKE-MLThre-256
Discovery: Moderate
Exploitation: About 2^127.89 work after 2^69 ciphertexts, or 2^255.78 work after 2^73 ciphertexts
Credit: Markku-Juhani O. Saarinen <markku-juhani.saarinen@tuni.fi>, with AI assistance
Date: 2026-09-30

Additional reference: [May and Sá Diogo, *Multi-Instance Security Degradation of Code-Based KEMs*, ePrint 2026/517, pinned 2026-06-12 version](https://eprint.iacr.org/archive/2026/517/20260612:161211)

Each encapsulation under one public key gives a new syndrome for an independently sampled weight-`t` error. May and Sá Diogo's same-key DS-DOOM attack searches all such targets together and returns the error for one observed ciphertext. In BIKE-MLThre, that error recovers the masked seed `m` and hence the shared key `KDF(m,c0,c1)`.

Applying the authors' pinned estimator to the submitted dimensions gives the first below-target crossings:

| set | observed ciphertexts | log2(bit operations) | log2(memory bits) | target |
|---|---:|---:|---:|---:|
| BIKE-MLThre-128 | 2^69 | 127.890 | 96.189 | 128 |
| BIKE-MLThre-256 | 2^73 | 255.780 | 103.648 | 256 |
| BIKE-MLThre-512 (control) | 2^80 | 513.965 | 114.390 | 512 |

The crossings use fewer than the evaluation ceiling of 2^80 ciphertexts under one public key and no decapsulation oracle. The NGCC call gives signatures a 2^64 per-key message requirement but gives KEMs no corresponding session cap. BIKE-MLThre explicitly discusses static-key deployments and key-reuse exposure (specification §3.4, physical pages 30–31). A hypothetical 2^64-ciphertext limit would avoid these two crossings, but it is neither specified nor enforced. The attacks therefore fall just below the 128- and 256-bit targets under the pinned estimator and are Critical under the classification policy.

The margins are only 0.110 and 0.220 bits, and the estimator reports large memory costs of `2^96.189` and `2^103.648` bits. One fewer session exponent puts each estimate back above its target. The classification is consequently sensitive to estimator precision, time-memory accounting, and alternative ISD cost models; the report does not claim a robust multi-bit shortfall.

### Reproducing

Install `numpy` and `scipy`, then run:

```sh
python3 kem-05/reproduce_multi_instance.py
```

The witness downloads the official estimator at commit `39b78dcc077793cfa3ccdce8d032ece76825ca55`, verifies both its archive and `doom.py` hashes, reproduces each crossing and its preceding above-target point, and checks the 512-bit control.
