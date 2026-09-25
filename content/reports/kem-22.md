<!-- synchronized report: kem-22/report.md -->
Candidate: Mithril
Family: Lattice (radical-ring LWR)
Archive: [Mithril.zip](https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/Mithril.zip) (SHA-256: `9fed68e7923c6bc9ede072183f7d3983058f88deec5534e779ed2200ee4f7f9f`)

## kem-22-1: Reversed decryption offset invalidates the failure estimate

Severity: Medium
Status: Confirmed
Layer: Design
Affected: All Mithril sets use the formula; full KEM mismatch reproduced for Mithril-256
Discovery: Moderate
Exploitation: Honest encapsulation/decapsulation can disagree; attack probability and key-recovery impact unmeasured
Credit: Samuel J. G. G. (GitHub @SamuelJGG)
Date: 2026-09-23
Original source: [GitHub issue #15](https://github.com/ngcc-dev/ngcc-harness/issues/15)

Encryption adds `q/(2p)` before compressing `c_m`. Algorithm 1 specifies `p/(2t) - q/(2p)` during decryption, and the live decoder in `arith/packing.c:215` applies the corresponding `+126` for Mithril-256. (The similar `poly_subp` in `pke.c` is unused.) Centering the compression remainder instead requires `q/(2p) - p/(2t)`. The specified sign leaves the Mithril-128/-256 decoder substantially off center, whereas the submitted decryption-failure analysis assumes a centered error. The report does not establish a new key-recovery attack or a numerical honest-failure probability.

Samuel's concrete Mithril-256 record uses the submitters' own PKE and KEM functions: an honestly formed ciphertext gives different encapsulated and decapsulated secrets. Its wrong bit has LWR noise 136 and compression remainder 254; the specified offset yields 514, beyond the decision margin 512, while the centered offset yields 262. This pinned record depends on the submitted hash output and need not persist under an ideal replacement, but the erroneous decoder offset is independent of that hash choice.

### Reproducing

```sh
D=kem-22/Implementations/Reference_Implementation/Mithril-256
T=$(mktemp -d)
gcc -O2 -DRRLWR_SECURITY_LEVEL=256 -I"$D" -I"$D/utils" -I"$D/arith" \
    "$D"/arith/{poly,ring,packing,uniform}.c "$D"/{pke,kem}.c \
    "$D"/utils/{auxfunc,drng}.c kem-22/reproduce_decoding_constant.c -o "$T/repro"
"$T/repro"
```

The program prints `CONFIRMED` only when the official decapsulator returns a different secret for the pinned honest encapsulation. It does not estimate the failure rate.
