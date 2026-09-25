<!-- synchronized report: sign-24/report.md -->
Candidate: Sigurd
Family: Code-based (regular syndrome decoding)
Archive: [Sigurd.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Sigurd.zip) (SHA-256: `443ab14257658d89a60e14ad0d4b7f4df9fcdd06da4f42fcb29bbbfc75a97153`)

## sign-24-1: Chunked Reed–Solomon encoding reveals the signing witness

Severity: Critical
Status: Confirmed
Layer: Implementation
Affected: Sigurd-128, -256, and -512 reference implementations
Discovery: Moderate
Exploitation: Witness recovery and accepted fresh-message forgeries from 4–8 ordinary signatures in independent tests
Credit: OpenAI Codex (Daybreak Blue), disclosed by Martin Feussner
Date: 2026-09-25
Original source: [Feussner's pqc-forum post and attached analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/2lO14yYyDK4/m/UYKYkWM7BAAJ)

The specification's vector commitment pads the witness with fresh random tail elements and applies one Reed–Solomon encoding. The submitted `RS_encode` instead divides the input into 32 independently encoded chunks (`sig_core.c:640–745` in Sigurd-128; the same structure appears in the other reference sets). Early chunks contain only the unchanged witness prefix; the fresh tail cannot hide their evaluations. Signatures expose selected encoded-witness symbols, so openings accumulated across signatures interpolate those chunks. The public syndrome then determines the short remaining witness suffix. An independent whole-scheme witness recovered all 217/458/946 blocks from 4–8 ordinary signatures and forged a fresh message accepted by each submitted verifier; changing one recovered one-hot block made the control forgery reject. The flaw is in the submitted encoding, not the specified single-code construction.

### Reproducing

```sh
make -C sign-24 exploit
tools/reproduce.sh sign-24
```

The independent driver queries `sig_sign` for ordinary signatures, parses only public transcripts, interpolates witness-only chunks, solves the remaining public-syndrome system, and calls the submitted `Prover` with the recovered witness. The original [forum analysis](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/2lO14yYyDK4/m/UYKYkWM7BAAJ) reports broader 35-key testing; our witness tests two different keys at each level.
