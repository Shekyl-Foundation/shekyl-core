# Generalized Bulletproofs

An implementation of
[Generalized Bulletproofs](</audits/generalized-bulletproofs/Security Proofs.pdf>),
a variant of the Bulletproofs arithmetic circuit statement to support Pedersen
vector commitments.

This library was audited in January, 2025 by Aaron Feickert, working for Cypher
Stack. Any subsequent changes have not undergone auditing. For reference,
please see the [audit](/audits/generalized-bulletproofs) and read the message
for the monero-oxide Git repository's commit
124ee09ba9d31b54b6fe4ff15d531a399bc18c99
(`git show 124ee09ba9d31b54b6fe4ff15d531a399bc18c99`).

### 'Fixed'

[Cypher Stack posted about a flaw in Generalized Bulletproofs protocol](
  https://github.com/cypherstack/generalized-bulletproofs-fix
) and published a new definition which modified the indexes in response. This
library adopts the changes to indexing as described in that paper. These
changes occurred after the aforementioned audit.

## Soundness assumption (Shekyl, `A5-12`)

Generalized Bulletproofs is an argument of knowledge whose soundness rests on
the **discrete-logarithm assumption** for the Pedersen generators (the
security proofs above are in that model). A prover holding a discrete-log
relation between generators can forge any statement; the arguments are not
post-quantum sound. Every Shekyl consumer of this crate — the FCMP++
membership proof and its `PL-D3` leaf-commitment opening leg — inherits
exactly this assumption and no stronger one (`docs/design/FCMP_SPEND_LINKABILITY.md`
§4).

