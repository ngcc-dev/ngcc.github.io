<!-- synchronized report: hash-14/report.md -->
Candidate: Laurus
Family: Symmetric (permutation-based)
Archive: [Laurus.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/Laurus.zip) (SHA-256: `9499a772e532577f85902c0f631a95af8e2fb4bc308da6466c076debd63d1415`)

## hash-14-1: Laurus loses its function-domain separation at c=1024

Severity: Medium
Status: Confirmed
Layer: Design
Affected: Specified generic `Laurus[c,fid]` interface at `c=1024`; the named XOF fixes `c=512`
Discovery: Moderate
Exploitation: Trivial
Credit: Tsinghua Hash Lab <cuihr26@mails.tsinghua.edu.cn>
Date: 2026-09-22
Original source: [CryptHashForum report](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/YGSFWSHQSIOIFIJTX6IBSDQCV25WS7I2/)
Follow-up source: [Laurus team's 2026-09-24 response](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/CC2SBG5TUNBN5ZD2WWEKITUQEVNJD56L/)

The specification uses `fid=0` for hashing and `fid=1` for XOF operation, placing the identifier only in the initial state. At `c=1024`, a message of 513 to 1024 bits causes one 512-bit absorption. That absorption omits the identifier from the permutation input and moves its difference into the first eight state words; finalization then discards exactly those words. The complete output is consequently independent of `fid`.

For example, the 768-bit all-zero message has identical 1024-bit outputs under `Laurus[1024,0]` and `Laurus[1024,1]`. This is a functional-domain separation failure in the normative generic interface, not a collision between distinct messages in a named fixed-output hash. The submitted `Laurus-XOF` wrapper fixes `c=512`, so it does not expose this particular pair through the uniform API.

The [Laurus team confirmed the generic-interface defect](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/CC2SBG5TUNBN5ZD2WWEKITUQEVNJD56L/) while reiterating that the named XOF uses `c=512`; they proposed repeating the function-ID-bearing initialization value across all three 512-bit state segments in an erratum. The archived specification remains the target here.

### Reproducing

The target exposes the otherwise internal generic interface from the submitted source, checks the 768-bit equality, and checks a 512-bit negative control:

```sh
make -C hash-14 reproduce
```
