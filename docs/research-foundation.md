# Research foundation

## Source material reviewed

The workspace contains the Leslie–Dutta paper, *A Traceable Threshold Asmuth–Bloom Secret Sharing Scheme* (27 pages), and the RiskShare project description. The requested Shamir 1979 and Forouzan references were not present. They are not used here to support detailed claims.

## Paper contribution

Leslie and Dutta introduce additive variants ABSS-I and ABSS-II of Asmuth–Bloom secret sharing, then construct TTSS-I and TTSS-II. Their design addresses tracing leaks using black-box access to a reconstruction box. TTSS-II hides first-component share residues behind exponentiation in a cyclic group, aiming to prevent a tracing-key holder from fabricating convincing accusations; its stated non-imputability argument relies on discrete-log hardness. These are the paper's formal constructions and claims, not claims established by this project.

## Construction outline

For threshold `t` among `n` parties, choose pairwise coprime integers `m0 < m1 < ... < mn` with `m0` prime and

`M = product(m1 ... mt) > m0 * product(m(n-t+2) ... mn)`.

Write the secret as an integer sum `s = s1 + ... + st`. The first component is encoded as `y1 = s1 + A1`, with `A1` public. The remaining components are encoded as `yj = sj + Aj*m0`, with private random multipliers. Each party receives residues `yj mod mi` for all components. Any `t` distinct shares give enough pairwise-coprime congruences to recover the encoded values with CRT; the bounded encoding makes those CRT representatives unique. Reconstruction obtains `s1` from `y1 - A1`, each later component modulo `m0`, then sums them.

TTSS-I additionally stores the encoded later components and first-component residues for a tracer. The tracing algorithm builds random auxiliary shares consistent with the later components, queries a reconstruction box, derives a candidate first encoded component, and compares its residues to identify the hardcoded shares. Its proof is that candidate integer; verification checks residue matches. TTSS-II replaces exposed residues with group exponentiation values and uses a cyclic group with an order large enough to preserve the intended residue comparisons. The paper's exact Algorithms 1–8 are the normative source for completing these modules.

## Assumptions and implementation boundary

- Pairwise-coprime moduli and the strict Asmuth–Bloom product inequality are required for CRT correctness and the stated secrecy argument.
- The paper's algorithms use idealized/asymptotic random inputs and a group-generation algorithm. A concrete product must specify finite distributions, parameter sizes, and supported secret ranges.
- The uploaded paper's TTSS-II pseudocode describes `g > mn`; an element of a group cannot be compared this way. This implementation interprets the intended requirement as group order `q > mn`, which makes the residue-to-scalar map injective over every share modulus.
- TTSS-II uses standardized secp384r1 or secp521r1. Its additive scalar multiplication is the EC-group equivalent of multiplicative exponentiation. The SEC 2 standard specifies these curve domain parameters and base point orders.
- Plain ABSS residues are unauthenticated. CRT correctness does not detect tampering; transport authentication, node signatures, epoch binding, and authorization are separate system controls.
- A finite test suite can check implementation behavior but cannot prove information-theoretic secrecy, universal traceability, or non-imputability.

## Research gap and RiskShare extension

The project description's research gap is operational: the base scheme fixes `t` at sharing time, while an adaptive policy wants recovery requirements to respond to measured risk. A stored share set cannot be re-labelled from 2-of-5 to 4-of-5. RiskShare therefore treats a threshold change as a new cryptographic epoch: make a fresh DEK, re-encrypt inside a restricted worker, create fresh shares under the new threshold, distribute and verify them, then atomically activate that epoch. Risk scoring and epoch transitions are application-level extensions and must be evaluated experimentally; they are not contributions of Leslie and Dutta.

## What is implemented and what remains

Implemented in the current milestones: ABSS-I Share/Rec with probable-prime parameter generation, pairwise-coprime moduli, strict inequality validation, additive components, CRT, and separate tracing/verification material; bounded TTSS-I tracing with reconstruction-box access; ABSS-II sharing/reconstruction; and TTSS-II tracing with group-point commitments and public verification. The implementation is finite-domain and handles nonnegative integer secrets. Default `m0` is sized from the secret bit width with at least 64 bits of headroom, rather than set just above the secret; deployments still need a fixed, documented secret domain and appropriately sized modulus.

Implemented beyond the sharing schemes: AES-256-GCM helpers with vault/epoch/version additional authenticated data and fixed-width DEK conversion; deterministic risk scoring and quorum policy primitives; and an in-memory hash-chained audit log. These components are not yet integrated into end-to-end workflows.

Not yet implemented: isolated recovery/epoch worker, five node agents, authenticated transport, recovery orchestration, persistent API/database, UI, attack simulation, and measured evaluation. The traceability/non-imputability theorems are not established by prototype tests; TTSS-I's tracing query budget and the concrete TTSS-II instantiation need cryptographic review.

## Reference

Maria Leslie and Ratna Dutta, “A Traceable Threshold Asmuth–Bloom Secret Sharing Scheme,” uploaded reference PDF. The paper discusses Algorithms 1–8 and their stated security proofs. RiskShare follows the proposed applied extension described in the uploaded RiskShare project description.
