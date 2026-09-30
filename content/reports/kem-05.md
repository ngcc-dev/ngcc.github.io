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
