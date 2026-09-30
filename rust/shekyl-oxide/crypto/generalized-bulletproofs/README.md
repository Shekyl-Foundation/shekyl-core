# Generalized Bulletproofs

An implementation of
[Generalized Bulletproofs](</audits/generalized-bulletproofs/Security Proofs.pdf>),
a variant of the Bulletproofs arithmetic circuit statement to support Pedersen
vector commitments.

For the protocol's review and the library's auditing, please see its
[audit folder](/audits/generalized-bulletproofs).

## Soundness assumption (Shekyl, `A5-12`)

Generalized Bulletproofs is an argument of knowledge whose soundness rests on
the **discrete-logarithm assumption** for the Pedersen generators (the
security proofs above are in that model). A prover holding a discrete-log
relation between generators can forge any statement; the arguments are not
post-quantum sound. Every Shekyl consumer of this crate — the FCMP++
membership proof and its `PL-D3` leaf-commitment opening leg — inherits
exactly this assumption and no stronger one (`docs/design/FCMP_SPEND_LINKABILITY.md`
§4).
