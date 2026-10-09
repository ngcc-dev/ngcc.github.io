<!-- synchronized report: hash-34/report.md -->
Candidate: WChain Hash Function
Family: Symmetric (iterated hash)
Archive: [WChain.zip](https://www.niccs.org.cn/niccs/Proposal/Cryptographic%20Hash%20Algorithms/Round%201%20candidates/WChain.zip) (SHA-256: `1ffeb0bd3f3645ea43decaacb0233c7dd23b9b127ac092efc0c12d6661f84023`)

## hash-34-1: A four-block reset prefix gives second preimages below the required levels

Severity: Critical
Status: Probable
Layer: Design
Affected: WChain-V1-512 and WChain-V2-1024
Discovery: Moderate
Exploitation: Reporter estimates about 2^292 and 2^580 work to find one reusable reset prefix; no full-size matching pair has been computed
Credit: Bishwajit Chakraborty
Date: 2026-10-09
Original source: [Chakraborty's WChain analysis](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/VGEPD4W2SY3QKSBGYKAGDMLSBXU5UEVR/)

WChain uses `CF(V,B)=P_B(V)⊕V`, two-step feedback `H_i=CF(H_{i−1},M_i)⊕H_{i−2}`, an XOR checksum of padded blocks, and zero initial states (specification §3 and §5.1, physical pp. 6–8, 18–20; reference `wchain_c.c:297–330,372–437`). Suppose full blocks `X,Y` satisfy `P_X(0)=P_Y^{-1}(0)=A`. Then `CF(0,X)=CF(A,Y)=A`; absorbing `X‖Y‖Y‖X` visits states `A,A,0,0` and adds zero to the checksum. Consequently, for every message `M`, `Hash(X‖Y‖Y‖X‖M)=Hash(M)` after ordinary padding and finalization.

A meet-in-the-middle search matches `P_X(0)` with `P_Y^{-1}(0)` in roughly `2^(b/2)` evaluations and comparable memory for a `b`-bit state (`b=576` or `1152`). The reporter's larger round-equivalent estimates, about `2^292` and `2^580`, remain far below the [NGCC-required](https://www.niccs.org.cn/niccs/Notice/crlRB1ZY.pdf) `2^512` and `2^1024` second-preimage levels. The state-reset identity follows exactly from the submitted mode. Its full-size cost assumes birthday-like behavior of the submitted message-keyed permutations; neither a full-size pair nor a full-size second preimage has been computed, hence Probable.

### Reproducing

```sh
python3 hash-34/reproduce_reset_prefix.py
```

The certificate checks the frozen reference source's feedback, checksum and finalization paths, then finds a matching pair and verifies the identity in a reduced-width permutation model. It does not claim to execute the full-size search.

## hash-34-2: Short-message checksum cancellation defeats the stated length-extension argument

Severity: Medium
Status: Confirmed
Layer: Design
Affected: WChain-V1-512 and WChain-V2-1024
Discovery: Moderate
Exploitation: A two-hash-query relation can be checked with 2^64 or 2^128 offline compression evaluations; no collision, second preimage, or one-query extension forgery is shown
Credit: Liting Zhang
Date: 2026-10-09
Original source: [Zhang's WChain analysis](https://list.niccs.org.cn/archives/list/crypthashforum@list.niccs.org.cn/message/K4VVZ3FDHGSZ7O7BGEC3ONLT7TYVJX44/)

For a message `m` shorter than one block, let `p` be its single padded block. The first two feedback terms vanish, so `Hash(m)=Trunc(CF(CF(0,p),p))`. For `m'=p‖m`, padding gives `p‖p` and the checksum is zero. Thus, if `H=CF(CF(0,p),p)` is the full final state, `Hash(m')=Trunc(CF(H,0))`. The digest reveals all but 64 bits of `H` in V1 or 128 bits in V2 (specification §3 and §5.1.1, physical pp. 6–8, 18–19; reference `wchain_c.c:326–330,371–437,445–479`). Enumerating those hidden bits therefore gives a candidate set that contains the second digest, contrary to §5.1.1's statement that the attacker would additionally need a pre-finalization state and checksum relation.

This is a restricted short-message relation, not a demonstrated arbitrary-message length-extension forgery. Without the second hash response or a verification oracle, enumeration alone does not identify which candidate is correct. WChain makes no indifferentiability claim, and this finding establishes no violation of the call's collision or preimage targets.

### Reproducing

```sh
python3 hash-34/reproduce_two_query_relation.py
```

The witness builds the submitted reference compression and hash functions in a temporary directory. At both levels it checks the relation using the full internal state, verifies that the published digest is its prefix, and checks changed-message and changed-hidden-word controls. It does not perform the 2^64 or 2^128 enumeration.
