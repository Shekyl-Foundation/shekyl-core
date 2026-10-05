# Full-Chain Membership Proofs

An implementation of the membership proof from
[FCMP++](https://github.com/kayabaNerve/fcmp-ringct/blob/develop/fcmp%2B%2B.pdf),
which inputs a re-randomized key, re-randomized linking tag generator, a
Pedersen commitment to the linking tag generator, and an amount commitment
before verifying there is a known de-re-randomization for a member of a Merkle
tree.

## Soundness assumption (Shekyl, `A5-12`)

Every statement this crate proves — tree membership, the key-image and
commitment re-randomisations, and Shekyl's `PL-D3` leg that opens the spent
leaf's PQC commitment `CM = K + r·J` to the verifier-supplied point `K` — is an
argument of knowledge under Generalized Bulletproofs, whose soundness rests on
the **discrete-logarithm assumption** in the Helios / Selene / Ed25519 groups
(the generators are NUMS; a prover who knows a discrete-log relation between
them can forge). It is therefore **classically sound only**: an adversary with
a discrete-log oracle can prove membership of a leaf it does not own and can
open any leaf's `CM` to any `K` of its choosing. The post-quantum authority of
a Shekyl spend does **not** come from this crate; it comes from the ML-DSA-65
signature under the revealed key, whose binding to the spent leaf this crate
provides only against a classical prover
(`docs/design/FCMP_SPEND_LINKABILITY.md` §4, `PL-D2`; `PL-D4` names the
successor mechanism).

