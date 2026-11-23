// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `KeyEngine::sign_transaction` bridge (Phase 2a §3.7–3.9).

use std::borrow::Cow;
use std::collections::HashMap;
use std::num::NonZeroU64;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::EdwardsPoint;
use shekyl_address::{MultisigAddressPayload, Network, PaymentAddress, ShekylAddress};
use shekyl_bulletproofs::Bulletproof;
use shekyl_crypto_pq::account::AllKeysBlob;
use shekyl_crypto_pq::derivation::derive_pqc_public_key;
use shekyl_crypto_pq::handle::derive_output_handle;
use shekyl_crypto_pq::label::sentinel_plaintext;
use shekyl_crypto_pq::TxKey;
use shekyl_network::NetworkId;
use shekyl_tx_builder::outputs::{BuildSpendError, BuiltSpend, Payee, Recipient, RecipientKeys};
use shekyl_tx_builder::{
    phase1_payload_hashes, sign_pqc_auths, sign_transaction as tx_sign_proofs,
    tx_prefix_hash_from_parts, InternalSignFault, LeafEntry, OutputInfo, PqcAuth, SignFault,
    SignedProofs, SpendInput, WireEncodeInput,
};
use shekyl_units::AtomicUnits;

use super::error::KeyEngineError;
use super::fee_variant::{fee_and_change, FeeVariantFault};
use super::local_keys::LocalKeys;
use super::pending::TxDestination;
use super::traits::key::{
    TxInputSignature, TxInputSigningContext, TxOutputContext, TxSignatures, TxToSign,
};
use crate::outbound_label::label_plaintext_for_recipient;

struct DerivedScalars {
    spend_public: EdwardsPoint,
}

impl DerivedScalars {
    fn from_keys(keys: &AllKeysBlob) -> Self {
        let spend_public = CompressedEdwardsY(*keys.spend_pk.as_canonical_bytes())
            .decompress()
            .expect("AllKeysBlob::spend_pk decompresses");
        Self { spend_public }
    }

    /// Spend key for a self-paid change output: the wallet's **base** spend key
    /// `D = b·G`. V3.0 is primary-only and the spend witness carries no claim
    /// offset (`x = ho + b`; see `LocalKeys::derive_primary_source_secrets_bundle`),
    /// so change MUST be paid to the base key — the same key any external sender
    /// pays to — for the wallet to detect it (scanner `B' == D`) and spend it
    /// (SAL open) later. The pre-fix `D + m₀·G` change was unspendable AND
    /// invisible to the scanner.
    fn change_spend_pk(&self) -> [u8; 32] {
        self.spend_public.compress().to_bytes()
    }
}

/// Assemble the transfer-shaped [`WireEncodeInput`] shared by the ordinary
/// transfer path ([`sign_tx`]) and the F-D2 drain
/// ([`assemble_drain_tx`](super::drain_assembly::assemble_drain_tx)).
///
/// This is the **single definition** of a confidential FCMP++ spend's wire
/// shape: empty `extra_inputs` (no bond/emission prefix input), all-zero
/// `output_amounts` (every vout confidential), and exactly one *placeholder*
/// `pqc_auth` per spend — public key only; the signature is filled by the
/// caller's [`phase1_payload_hashes`] + [`sign_pqc_auths`] pass. Because both
/// paths route through here, a drain's full wire serialization is
/// transfer-identical **by construction** rather than by a hand-copied literal
/// that could silently drift — this is the enforcement mechanism for the
/// T-DS-6 ∧ T-DS-7 composite wire-shape arm (`ARCHIVAL_DRAIN_SEND_FD2.md` §5),
/// not a test that green-checks each sub-surface separately.
///
/// `pqc_pubkeys` is one serialized hybrid public key per spend input, in the
/// same (strict-descending key-image) order as `key_images`.
///
/// `signed` is taken **by value**: the constructor moves its large proof buffers
/// (`enc_amounts`, `enc_labels`, `commitments`, `pseudo_outs`, `fcmp_proof`)
/// straight into the [`WireEncodeInput`] rather than cloning them. The drain
/// path — which discards `signed` after this call — passes it by move for free;
/// [`sign_tx`], which still needs the proofs to build its [`TxSignatures`],
/// hands in a `signed.clone()`. Keeping this one owning constructor (rather than
/// a borrowed + owned pair) is what preserves the "one constructor, two callers"
/// compile-time transfer-parity guarantee for T-DS-6 ∧ T-DS-7.
///
/// Returns [`KeyEngineError::Primitive`] if the documented length invariants are
/// violated — `view_tags` must be per-output (align with `output_keys`) and
/// `pqc_pubkeys` must be one-per-spend (align with `key_images`) — so a caller
/// mismatch fails here with a precise message instead of surfacing later as an
/// opaque `phase1_payload_hashes`/wire-encode error.
pub(super) fn assemble_transfer_wire(
    key_images: Vec<[u8; 32]>,
    output_keys: Vec<[u8; 32]>,
    view_tags: Vec<Option<u8>>,
    tx_extra: Vec<u8>,
    fee: u64,
    signed: SignedProofs,
    pqc_pubkeys: &[Vec<u8>],
) -> Result<WireEncodeInput, KeyEngineError> {
    if view_tags.len() != output_keys.len() {
        return Err(KeyEngineError::Primitive {
            detail: "assemble_transfer_wire: view_tags length must equal output_keys length",
        });
    }
    if pqc_pubkeys.len() != key_images.len() {
        return Err(KeyEngineError::Primitive {
            detail: "assemble_transfer_wire: pqc_pubkeys length must equal key_images length",
        });
    }

    let bulletproof =
        Bulletproof::read_plus(&mut signed.bulletproof_plus.as_slice()).map_err(|_| {
            KeyEngineError::Primitive {
                detail: "bulletproof parse failed",
            }
        })?;
    let output_amounts = vec![0u64; output_keys.len()];
    Ok(WireEncodeInput {
        key_images,
        extra_inputs: Vec::new(),
        output_amounts,
        output_keys,
        view_tags,
        tx_extra,
        fee,
        enc_amounts: signed.enc_amounts,
        enc_labels: signed.enc_labels,
        out_commitments: signed.commitments,
        pseudo_outs: signed.pseudo_outs,
        bulletproof,
        reference_block: signed.reference_block,
        fcmp_proof: signed.fcmp_proof,
        pqc_auths: pqc_pubkeys
            .iter()
            .map(|pk| PqcAuth {
                auth_version: shekyl_tx_builder::PQC_AUTH_VERSION,
                scheme: shekyl_tx_builder::PqcScheme::Single,
                signature: Vec::new(),
                public_key: pk.clone(),
            })
            .collect(),
        fcmp_layers: signed.tree_depth,
    })
}

fn decode_recipient(address: &str, network: Network) -> Result<ShekylAddress, KeyEngineError> {
    PaymentAddress::decode(address, network)
        .map(PaymentAddress::into_inner)
        .map_err(|_| KeyEngineError::Primitive {
            detail: "invalid recipient address",
        })
}

/// Resolve a payment's destination to the keys its output is built to. An
/// address goes through [`shekyl_address::PaymentAddress`]; the request
/// was already refused before selection if it cannot be paid
/// ([`super::pending::TxRequest::check_recipients`]), so a failure here is
/// a signer fault, not a user's typo. A persona's keys are used exactly as
/// the stake engine handed them over, with nothing encoded or decoded.
fn recipient_keys(
    destination: &TxDestination,
    network: Network,
) -> Result<PaymentKeys<'_>, KeyEngineError> {
    let (spend_key, view_key, ml_kem_ek): (_, _, Cow<'_, [u8]>) = match destination {
        TxDestination::Address(address) => {
            let decoded = decode_recipient(address, network)?;
            (
                decoded.spend_key,
                decoded.view_key,
                Cow::Owned(decoded.ml_kem_encap_key),
            )
        }
        TxDestination::OwnPersona(persona) => (
            *persona.spend_pk().as_canonical_bytes(),
            *persona.view_pk().as_canonical_bytes(),
            Cow::Borrowed(persona.ml_kem_ek().as_slice()),
        ),
        // A group's address is its keys: the builder encapsulates to the
        // group's KEM key and each member's (`Payee::Group`).
        TxDestination::Group(group) => return Ok(PaymentKeys::Group(group.address())),
    };
    RecipientKeys::from_edwards(spend_key, &view_key, ml_kem_ek)
        .map(PaymentKeys::Single)
        .map_err(|_| KeyEngineError::Primitive {
            detail: "recipient view key does not map to a valid X25519 point",
        })
}

/// What one payment's output is built to: a single signer's keys, or a
/// group's address (R-37).
enum PaymentKeys<'a> {
    Single(RecipientKeys<'a>),
    Group(&'a MultisigAddressPayload),
}

impl PaymentKeys<'_> {
    /// The payee the builder takes. A group output's label is always the
    /// sentinel, so `label_plaintext` is a single signer's alone; the
    /// request refuses a payment request (`rid`) for a group before any
    /// selection.
    fn payee<'p>(&'p self, label_plaintext: &'p [u8; 8], network: &'p NetworkId) -> Payee<'p> {
        match self {
            Self::Single(keys) => keys.payee(label_plaintext),
            Self::Group(address) => Payee::Group { address, network },
        }
    }
}

fn spend_input_from_context(
    ctx: &TxInputSigningContext,
    bundle: &super::traits::key::SourceSecretsBundle,
    leaf_chunk: Vec<LeafEntry>,
    c1_layers: Vec<Vec<[u8; 32]>>,
    c2_layers: Vec<Vec<[u8; 32]>>,
) -> SpendInput {
    SpendInput {
        output_key: ctx.output_key,
        commitment: ctx.commitment,
        amount: ctx.amount,
        spend_key_x: *bundle.spend_key_x,
        spend_key_y: *bundle.spend_key_y,
        commitment_mask: *bundle.commitment_mask,
        combined_ss: bundle.combined_ss.to_vec(),
        output_index: ctx.internal_output_index,
        leaf_chunk,
        c1_layers,
        c2_layers,
    }
}

/// Sign a populated [`TxToSign`] using wallet key material (actor round-trip).
/// One payment output the sign pass will construct, its label plaintext
/// already chosen so the construction loop only encrypts.
struct PaymentOutput {
    destination: TxDestination,
    amount: u64,
    label_plaintext: [u8; 8],
}

/// The payment outputs of a sign request, each with the label plaintext
/// `outbound_label` chose for its destination, and their total. `Change`
/// intents carry nothing here: V3.0 is primary-only, change always returns
/// to the base spend key, and its amount is the leftover the caller derives.
fn payment_outputs_of(
    outputs: &[TxOutputContext],
) -> Result<(u64, Vec<PaymentOutput>), KeyEngineError> {
    let mut total = 0u64;
    let mut payments = Vec::new();
    for output in outputs {
        if let TxOutputContext::Payment { dest, amount } = output {
            total = total
                .checked_add(*amount)
                .ok_or(KeyEngineError::InsufficientFunds { shortfall: 0 })?;
            payments.push(PaymentOutput {
                destination: dest.destination.clone(),
                amount: *amount,
                label_plaintext: label_plaintext_for_recipient(dest.rid)?,
            });
        }
    }
    Ok((total, payments))
}

impl From<BuildSpendError> for KeyEngineError {
    fn from(fault: BuildSpendError) -> Self {
        match fault {
            BuildSpendError::NoOutputs => Self::Primitive {
                detail: "no outputs after fee variant selection",
            },
            // The builder's own fault, the same keyword `sign_transaction`'s
            // refusal reports (`too-few-outputs`): no send path builds fewer
            // outputs than consensus admits, so reaching it is a bug.
            BuildSpendError::TooFewOutputs { .. } => {
                Self::Sign(SignFault::Internal(InternalSignFault::TooFewOutputs))
            }
            BuildSpendError::TooManyOutputs { count } => {
                Self::Sign(SignFault::TooManyOutputs { count })
            }
            BuildSpendError::Output { source, .. } => {
                Self::SourceCiphertextDecapsulationFailed(source)
            }
            BuildSpendError::Extra(_) => Self::Primitive {
                detail: "tx_extra does not encode",
            },
        }
    }
}

impl From<FeeVariantFault> for KeyEngineError {
    fn from(fault: FeeVariantFault) -> Self {
        match fault {
            // The build's selection covers the with-change fee and the least
            // change, so a short leftover is a bug. It keeps the builder's
            // insufficient-funds fault: the amounts do not balance at a
            // ladder fee. The shortfall stays in the local log.
            FeeVariantFault::Short { shortfall } => {
                tracing::debug!(shortfall, "a leftover no ladder fee balances");
                Self::Sign(SignFault::Internal(InternalSignFault::InsufficientFunds))
            }
            FeeVariantFault::TooManyOutputs { count } => {
                Self::Sign(SignFault::TooManyOutputs { count })
            }
        }
    }
}

pub(crate) fn sign_tx(local: &LocalKeys, tx: &TxToSign) -> Result<TxSignatures, KeyEngineError> {
    let keys = &local.keys;
    if tx.inputs.is_empty() {
        return Err(KeyEngineError::Primitive {
            detail: "sign_transaction requires at least one input",
        });
    }

    let derived = DerivedScalars::from_keys(keys);
    let network = tx.network;
    let tree_ctx = tx.fcmp_plus_plus_context.tree.clone();
    let fee_directive = tx.fee;

    let mut input_amounts = 0u64;
    for input in &tx.inputs {
        input_amounts = input_amounts
            .checked_add(input.amount.to_raw())
            .ok_or(KeyEngineError::InsufficientFunds { shortfall: 0 })?;
    }

    let (payment_total, payment_outputs) = payment_outputs_of(&tx.outputs)?;

    let leftover =
        input_amounts
            .checked_sub(payment_total)
            .ok_or(KeyEngineError::InsufficientFunds {
                shortfall: payment_total.saturating_sub(input_amounts),
            })?;

    let priced = fee_and_change(leftover, &fee_directive)?;
    let fee = priced.fee;
    let change = priced.change;

    // The transaction key: retained for the OUTBOUND proof (WI-RPC-3).
    let tx_key = TxKey::random()?;

    // Each payment's keys, mapped once (the view key to X25519 by
    // `RecipientKeys`); the recipients borrow them.
    let payment_keys = payment_outputs
        .iter()
        .map(|payment| recipient_keys(&payment.destination, network))
        .collect::<Result<Vec<_>, _>>()?;
    let change_pk = derived.change_spend_pk();
    let sentinel = sentinel_plaintext();
    let network_id = network.network_id();
    let mut recipients: Vec<Recipient<'_>> = payment_outputs
        .iter()
        .zip(&payment_keys)
        .map(|(payment, keys)| Recipient {
            payee: keys.payee(&payment.label_plaintext, &network_id),
            amount: payment.amount,
        })
        .collect();
    // A change is at least one unit (`fee_variant::fee_and_change`): when the
    // fee is the with-change fee, the change output is always built.
    if let Some(change_amount) = change.map(NonZeroU64::get) {
        recipients.push(Recipient {
            payee: Payee::Single {
                spend_key: &change_pk,
                view_x25519: &keys.x25519_pk,
                ml_kem_ek: &keys.ml_kem_ek,
                label_plaintext: &sentinel,
            },
            amount: change_amount,
        });
    }

    // The one builder every spend path uses places each output at the
    // position the key derives (R-24), so the change sits anywhere, and
    // writes tx_extra: the tx pubkey, every output's KEM ciphertext, and
    // the `0x07` leaf entries (CEN-I19).
    let built = BuiltSpend::build(&tx_key, &recipients)?;
    let built_outputs = built.outputs();
    let tx_extra = built.extra().to_vec();

    let mut bundles = HashMap::new();
    for input in &tx.inputs {
        let expected = derive_output_handle(
            keys.view_sk.as_canonical_bytes(),
            &input.tx_hash,
            input.internal_output_index,
        );
        if expected != input.handle {
            return Err(KeyEngineError::HandleMismatch {
                output_index: input.internal_output_index,
            });
        }

        let bundle = local.derive_primary_source_secrets_bundle(
            &input.source_ciphertext,
            input.internal_output_index,
        )?;
        // Key by the *globally unique* output identity `(tx_hash, output_index)`,
        // NOT `internal_output_index` alone: that index is per-transaction, so a
        // multi-input spend over coinbase outputs (each output 0 of its own tx)
        // would collide on key 0 and clobber all-but-one bundle, pairing every
        // input with the wrong `(x, y)`.
        bundles.insert((input.tx_hash, input.internal_output_index), bundle);
    }

    let mut spend_inputs = Vec::with_capacity(tx.inputs.len());
    let mut key_images = Vec::with_capacity(tx.inputs.len());
    let mut pqc_pubkeys = Vec::with_capacity(tx.inputs.len());

    // Consensus requires spend inputs strictly DESCENDING by key image
    // (`blockchain.cpp:3650`; shekyl-wire validate, `transaction.rs:1547`). The
    // FCMP++ proof binds the input order, so sort BEFORE building witnesses, key
    // images, and the proof — one canonical order shared by the proof, the wire
    // key-image list, and the returned per-input pseudo-outs. Distinct UTXOs ⇒
    // distinct key images, so the strict ordering never rejects our own tx.
    let mut sorted_inputs: Vec<_> = tx.inputs.iter().collect();
    sorted_inputs.sort_by(|a, b| b.key_image.as_bytes().cmp(a.key_image.as_bytes()));

    for input in sorted_inputs {
        let bundle = bundles
            .get(&(input.tx_hash, input.internal_output_index))
            .expect("bundle inserted above");
        let combined: [u8; 64] =
            bundle.combined_ss[..64]
                .try_into()
                .map_err(|_| KeyEngineError::Primitive {
                    detail: "combined_ss wrong length",
                })?;
        let pk = derive_pqc_public_key(&combined, input.internal_output_index)
            .map_err(KeyEngineError::SourceCiphertextDecapsulationFailed)?;

        if input.key_image.as_bytes().iter().all(|b| *b == 0) {
            return Err(KeyEngineError::MissingKeyImage {
                output_index: input.internal_output_index,
            });
        }
        // CT-5c: the membership path (leaf chunk + branch layers) is the *real*
        // path the curve-tree client assembled, threaded verbatim through the
        // signing context — not re-derived or padded here. The pre-CT-5c
        // synthetic re-run (`enrich_input_tree`) is gone; clobbering the real
        // branches with placeholders was the second of the two synthetic sites.
        spend_inputs.push(spend_input_from_context(
            input,
            bundle,
            input.leaf_chunk.clone(),
            input.c1_layers.clone(),
            input.c2_layers.clone(),
        ));
        key_images.push(*input.key_image.as_bytes());
        pqc_pubkeys.push(pk);
    }

    // CT-5c: the real tree context from the assembled paths, used verbatim. The
    // pre-CT-5c synthetic root overwrite (`synthetic_tree_root_from_leaf_chunk`)
    // is gone — `tree_ctx.tree_root` is the consensus root the proof anchors to.
    let tree = tree_ctx;

    let output_infos: Vec<OutputInfo> = built_outputs.iter().map(|b| b.info.clone()).collect();
    let output_keys: Vec<[u8; 32]> = built_outputs.iter().map(|b| b.output_key).collect();
    let view_tags: Vec<Option<u8>> = built_outputs.iter().map(|b| Some(b.view_tag)).collect();

    let prefix_hash = tx_prefix_hash_from_parts(&key_images, &output_keys, &view_tags, &tx_extra);

    let signed = tx_sign_proofs(
        &tx.network.network_id(),
        prefix_hash,
        &spend_inputs,
        &output_infos,
        AtomicUnits::from_raw(fee),
        &tree,
    )
    .map_err(|e| {
        // The inner text (a prover's or encoder's message) stays in the
        // local log; the fault that leaves is the variant, bounded.
        tracing::debug!(error = %e, "the transaction builder refused the signing pass");
        KeyEngineError::Sign(e.fault())
    })?;

    // The wire shape is assembled by the single shared constructor both this
    // path and the F-D2 drain route through, so the two serialize identically
    // by construction (T-DS-6 ∧ T-DS-7 — `ARCHIVAL_DRAIN_SEND_FD2.md` §5).
    // `key_images`/`output_keys`/`view_tags`/`tx_extra` and `signed` are cloned
    // in because this path still needs them below: the returned `TxSignatures`
    // echoes the buffers, moves `signed`'s proof fields, and `per_input`
    // re-walks the key images and `signed.pseudo_outs`. The drain path, which
    // discards these afterward, moves them in at zero clones.
    let mut wire_with_proofs = assemble_transfer_wire(
        key_images.clone(),
        output_keys.clone(),
        view_tags.clone(),
        tx_extra.clone(),
        fee,
        signed.clone(),
        &pqc_pubkeys,
    )?;

    let payload_hashes = phase1_payload_hashes(&wire_with_proofs, &tx.network.network_id())
        .map_err(|_| KeyEngineError::Primitive {
            detail: "phase1 payload hash failed",
        })?;

    let pqc_auths =
        sign_pqc_auths(&payload_hashes, &spend_inputs).map_err(|_| KeyEngineError::Primitive {
            detail: "pqc auth signing failed",
        })?;

    wire_with_proofs.pqc_auths = pqc_auths.clone();

    let per_input: Vec<TxInputSignature> = spend_inputs
        .iter()
        .zip(signed.pseudo_outs.iter())
        .zip(key_images.iter())
        .zip(pqc_auths.iter())
        .map(|(((_inp, pseudo), ki), auth)| TxInputSignature {
            key_image: shekyl_crypto_pq::key_image::KeyImage::from_canonical_bytes(*ki),
            pseudo_out: *pseudo,
            pqc_auth: auth.clone(),
        })
        .collect();

    Ok(TxSignatures {
        bulletproof_plus: signed.bulletproof_plus,
        out_commitments: signed.commitments,
        enc_amounts: signed.enc_amounts,
        enc_labels: signed.enc_labels,
        per_input,
        fcmp_proof: signed.fcmp_proof,
        fee,
        reference_block: signed.reference_block,
        tree_depth: signed.tree_depth,
        output_keys,
        view_tags,
        tx_extra,
        // WI-RPC-3 retention: the key leaves the signing frame instead of
        // dying at function exit; the submit path persists its stored form
        // at dispatch.
        tx_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::local_keys::LocalKeys;
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use shekyl_crypto_pq::kem::HybridCiphertext;
    use shekyl_crypto_pq::label::{classify_label_plaintext, LabelPlaintextKind};
    use shekyl_crypto_pq::montgomery::ed25519_pk_to_x25519_pk;
    use shekyl_crypto_pq::output::{construct_output, scan_output_recover};
    use shekyl_engine_state::PaymentRequestId;

    /// The production path from a destination's `rid` to the plaintext the
    /// sign pass encrypts: `payment_outputs_of` is what `sign_tx` calls, so
    /// a sentinel substituted for the request echo there fails here.
    #[test]
    fn the_sign_pass_chooses_the_request_echo_from_the_destinations_rid() {
        use super::super::traits::key::OutputDestination;
        let outputs = vec![
            TxOutputContext::Payment {
                dest: OutputDestination {
                    destination: TxDestination::Address("shekyl1payee".into()),
                    rid: Some(PaymentRequestId(42)),
                },
                amount: 5,
            },
            TxOutputContext::Change {
                subaddress_index: 0,
            },
            TxOutputContext::Payment {
                dest: OutputDestination {
                    destination: TxDestination::Address("shekyl1other".into()),
                    rid: None,
                },
                amount: 7,
            },
        ];
        let (total, payments) = payment_outputs_of(&outputs).expect("both rids are echoable");
        assert_eq!(total, 12);
        assert_eq!(payments.len(), 2, "change is not a payment output");
        assert_eq!(
            classify_label_plaintext(&payments[0].label_plaintext),
            LabelPlaintextKind::Request(42)
        );
        assert_eq!(payments[0].amount, 5);
        assert_eq!(
            classify_label_plaintext(&payments[1].label_plaintext),
            LabelPlaintextKind::Sentinel
        );
        let unechoable = vec![TxOutputContext::Payment {
            dest: OutputDestination {
                destination: TxDestination::Address("shekyl1payee".into()),
                rid: Some(PaymentRequestId(0)),
            },
            amount: 1,
        }];
        assert!(matches!(
            payment_outputs_of(&unechoable),
            Err(KeyEngineError::RidNotEncodable(_))
        ));
    }

    /// The bytes a transfer's outputs and `tx_extra` are made of, pinned for
    /// a fixed transaction key: a payment and a change output built by the
    /// builder `sign_tx` uses, in the order the key derives (R-24), and
    /// their `tx_extra`. Each output contributes its key, view tag,
    /// commitment and encrypted fields. The commitment is the point the
    /// chain carries; the mask stays a scalar. Output construction and
    /// order are deterministic given the transaction key, so a change to
    /// the builder that moves any byte of a solo transfer fails here.
    #[test]
    fn a_transfers_outputs_and_extra_are_pinned_for_a_fixed_tx_key() {
        const SEED: [u8; 32] = [21u8; 32];
        // A canonical scalar, so `seeded`'s reduction leaves it as it is.
        let tx_key = TxKey::seeded(Scalar::from(23u64).to_bytes());

        let recipient_keys = LocalKeys::from_test_seed(SEED);
        let address = recipient_keys
            .keys
            .to_address(Network::Mainnet)
            .encode()
            .expect("encode recipient address");
        let decoded = decode_recipient(&address, Network::Mainnet).expect("decode recipient");
        let recipient = RecipientKeys::of_address(&decoded).expect("the address's keys");
        let label = sentinel_plaintext();
        let recipients = [7_000_000u64, 2_500_000].map(|amount| Recipient {
            payee: recipient.payee(&label),
            amount,
        });
        let built = BuiltSpend::build(&tx_key, &recipients).expect("build the outputs");
        let mut transcript = built.extra().to_vec();
        for out in built.outputs() {
            transcript.extend_from_slice(&out.output_key);
            transcript.push(out.view_tag);
            transcript.extend_from_slice(
                &out.commitment_mask()
                    .opening(out.info.amount.to_raw())
                    .calculate()
                    .compress()
                    .to_bytes(),
            );
            transcript.extend_from_slice(&out.info.enc_amount.to_bytes());
            transcript.extend_from_slice(&out.info.enc_label.to_bytes());
        }
        assert_eq!(
            hex::encode(shekyl_crypto_hash::keccak256(&transcript)),
            "47afa9549cb26dd7d1fbaf3107f86ee64cebf0828377922c3acc016ceef4984e"
        );
    }

    /// A payment that answers a `shekyl:` link echoes the request id in its
    /// encrypted label and the recipient reads it back; a payment with no
    /// request carries the sentinel through the same construction. This is
    /// the wiring `sign_tx` relies on: the builder encrypts exactly the
    /// plaintext `outbound_label` chose for the destination, at whatever
    /// position the key puts its output.
    #[test]
    fn payment_output_label_echoes_the_recipients_request_id() {
        const SEED: [u8; 32] = [21u8; 32];
        const TX_KEY: [u8; 32] = [23u8; 32];
        const AMOUNT: u64 = 7_000_000;

        let recipient_keys = LocalKeys::from_test_seed(SEED);
        let address = recipient_keys
            .keys
            .to_address(Network::Mainnet)
            .encode()
            .expect("encode recipient address");
        let decoded = decode_recipient(&address, Network::Mainnet).expect("decode recipient");
        let recipient = RecipientKeys::of_address(&decoded).expect("the address's keys");

        let recover = |built: &shekyl_tx_builder::outputs::BuiltOutput, position: usize| {
            let (ct_x25519, ct_ml_kem) = built.kem_blob.split_at(32);
            let commitment = built
                .commitment_mask()
                .opening(AMOUNT)
                .calculate()
                .compress()
                .to_bytes();
            scan_output_recover(
                recipient_keys.keys.view_sk.as_canonical_bytes(),
                recipient_keys.keys.ml_kem_dk.as_canonical_bytes(),
                ct_x25519
                    .try_into()
                    .expect("the X25519 ciphertext is 32 bytes"),
                ct_ml_kem,
                &built.output_key,
                &commitment,
                built.info.enc_amount.ciphertext(),
                built.info.enc_amount.tag(),
                built.info.enc_label.ciphertext(),
                built.info.enc_label.tag(),
                built.view_tag,
                position as u64,
            )
            .expect("recipient recovers the payment output")
        };

        for (rid, expected) in [
            (None, LabelPlaintextKind::Sentinel),
            (
                Some(PaymentRequestId(12345)),
                LabelPlaintextKind::Request(12345),
            ),
        ] {
            let label = label_plaintext_for_recipient(rid).expect("an encodable rid");
            // A second recipient: no transaction carries fewer than two
            // outputs (CEN-I1). Recipient 0 is the one checked.
            let spend = BuiltSpend::build(
                &TxKey::seeded(TX_KEY),
                &[
                    Recipient {
                        payee: recipient.payee(&label),
                        amount: AMOUNT,
                    },
                    Recipient {
                        payee: recipient.payee(&label),
                        amount: 1,
                    },
                ],
            )
            .expect("construct payment output");
            let position = spend.position_of(0).expect("the payment's position");
            let built = &spend.outputs()[position];
            assert_eq!(
                classify_label_plaintext(&recover(built, position).label_plaintext),
                expected,
                "rid {rid:?}"
            );
        }
    }

    /// `stake_in`'s destination through the sign pass: a persona destination
    /// resolves to that persona's own keys with nothing encoded or decoded,
    /// and the output the builder makes from them is one the persona's
    /// scan recovers, owned by its spend key. A persona destination built
    /// from the wrong keys would leave an output nobody opens.
    #[test]
    fn a_persona_destination_builds_an_output_the_persona_recovers() {
        use crate::engine::stake_engine::test_fixtures::derive_bundle;
        const TX_KEY: [u8; 32] = [29u8; 32];
        const AMOUNT: u64 = 9_000_000;

        let persona = derive_bundle(2);
        let destination = TxDestination::OwnPersona(persona.payment_destination());
        // The network is the wallet's; a persona arm reads none of it.
        let PaymentKeys::Single(resolved) =
            recipient_keys(&destination, Network::Testnet).expect("resolve")
        else {
            panic!("a persona resolves to a single signer's keys");
        };
        assert_eq!(resolved.spend_key(), persona.spend_pk.as_canonical_bytes());
        assert_eq!(
            resolved.view_x25519(),
            &ed25519_pk_to_x25519_pk(persona.view_pk.as_canonical_bytes()).unwrap()
        );
        assert_eq!(resolved.ml_kem_ek(), &persona.ml_kem_ek[..]);

        let label = sentinel_plaintext();
        // A second recipient: no transaction carries fewer than two outputs
        // (CEN-I1). Recipient 0 is the one checked.
        let spend = BuiltSpend::build(
            &TxKey::seeded(TX_KEY),
            &[
                Recipient {
                    payee: resolved.payee(&label),
                    amount: AMOUNT,
                },
                Recipient {
                    payee: resolved.payee(&label),
                    amount: 1,
                },
            ],
        )
        .expect("construct the persona's output");
        let position = spend.position_of(0).expect("the persona's position");
        let built = &spend.outputs()[position];
        let (ct_x25519, ct_ml_kem) = built.kem_blob.split_at(32);
        let commitment = built
            .commitment_mask()
            .opening(AMOUNT)
            .calculate()
            .compress()
            .to_bytes();
        let recovered = scan_output_recover(
            persona.view_sk.as_canonical_bytes(),
            persona.ml_kem_dk.as_canonical_bytes(),
            ct_x25519
                .try_into()
                .expect("the X25519 ciphertext is 32 bytes"),
            ct_ml_kem,
            &built.output_key,
            &commitment,
            built.info.enc_amount.ciphertext(),
            built.info.enc_amount.tag(),
            built.info.enc_label.ciphertext(),
            built.info.enc_label.tag(),
            built.view_tag,
            position as u64,
        )
        .expect("the persona recovers the output");
        assert_eq!(recovered.amount, AMOUNT);
        assert_eq!(
            &recovered.recovered_spend_key,
            persona.spend_pk.as_canonical_bytes(),
            "the output is owned by the persona's spend key"
        );
    }

    /// A self-paid **change** output must return to the wallet's base spend key
    /// `D = b·G` so the wallet can both **detect** it (the scanner recovers
    /// `B' == D`) and **spend** it (the derived witness opens `O = x·G + y·T`).
    ///
    /// The pre-fix change path paid to `D + m₀·G`, which is *neither*: invisible
    /// to the scanner (which matches the base key) and unspendable (the witness
    /// is `x = ho + b`, no offset). The whole-tx north-star did not catch it —
    /// the daemon accepts the change output as a valid point regardless — so this
    /// is the direct guard against reintroducing the offset on the change side.
    #[test]
    fn change_output_returns_to_base_and_is_detectable_and_spendable() {
        const SEED: [u8; 32] = [7u8; 32];
        const TX_KEY: [u8; 32] = [11u8; 32];
        const OUT_IDX: u64 = 0;
        const AMOUNT: u64 = 1_000_000;

        let keys = LocalKeys::from_test_seed(SEED);
        let derived = DerivedScalars::from_keys(&keys.keys);

        // (1) change spend key is the bare base key — no claim offset.
        let change_pk = derived.change_spend_pk();
        assert_eq!(
            change_pk,
            *keys.keys.spend_pk.as_canonical_bytes(),
            "change must return to the base spend key D = b·G"
        );

        // Build the change output exactly as `sign_tx` does.
        let constructed = construct_output(
            TxKey::seeded(TX_KEY)
                .output_positions(usize::try_from(OUT_IDX).unwrap() + 1)
                .at(OUT_IDX)
                .unwrap(),
            &keys.keys.x25519_pk,
            &keys.keys.ml_kem_ek,
            &change_pk,
            AMOUNT,
        )
        .expect("construct change output");

        // (2) Detectable: the scanner recovers B' == the base spend key.
        let recovered = scan_output_recover(
            keys.keys.view_sk.as_canonical_bytes(),
            keys.keys.ml_kem_dk.as_canonical_bytes(),
            &constructed.kem_ciphertext_x25519,
            &constructed.kem_ciphertext_ml_kem,
            &constructed.output_key,
            &constructed.commitment,
            &constructed.enc_amount_bytes(),
            constructed.amount_tag(),
            &constructed.enc_label_bytes(),
            constructed.label_tag(),
            constructed.view_tag_prefilter,
            OUT_IDX,
        )
        .expect("scanner detects the self-paid change output");
        assert_eq!(
            recovered.recovered_spend_key, change_pk,
            "scanner must recover the base spend key for change"
        );

        // (3) Spendable: the derived witness opens the output key, x·G + y·T == O.
        let ciphertext = HybridCiphertext {
            x25519: constructed.kem_ciphertext_x25519,
            ml_kem: constructed.kem_ciphertext_ml_kem.clone(),
        };
        let bundle = keys
            .derive_primary_source_secrets_bundle(&ciphertext, OUT_IDX)
            .expect("derive change-output spend bundle");
        let x: Scalar =
            Option::from(Scalar::from_canonical_bytes(*bundle.spend_key_x)).expect("x canonical");
        let y: Scalar =
            Option::from(Scalar::from_canonical_bytes(*bundle.spend_key_y)).expect("y canonical");
        let o = CompressedEdwardsY(constructed.output_key)
            .decompress()
            .expect("O decompresses");
        assert_eq!(
            (&x * ED25519_BASEPOINT_TABLE) + (*shekyl_curve_generators::T * y),
            o,
            "change output must open with x·G + y·T == O (spendable)"
        );
    }

    /// A **payment** output built from a decoded address must be recoverable by
    /// the recipient — the sender-side X25519 encapsulation key is
    /// `montgomery(view_pk)`, never the raw Edwards `view_key` bytes the
    /// address carries.
    ///
    /// The pre-fix payment path passed `recipient.view_key` (compressed
    /// Edwards) straight into `construct_output`'s `x25519_pk` parameter, which
    /// interprets the bytes as a Montgomery u-coordinate. The ECDH then targets
    /// a wrong point: the daemon still accepts the transaction (the sender's
    /// own proofs re-derive from the same wrong point, consistently), but the
    /// recipient's decap silently fails and the payment is invisible to its
    /// scanner. Self-paid change never hit this (it uses the wallet's stored
    /// `x25519_pk`), so only a cross-wallet recovery pins it — this is the
    /// unit-level distillation of the PR-4 staker regtest harness's
    /// persona-funding discovery leg.
    #[test]
    fn payment_output_from_decoded_address_is_recoverable_by_the_recipient() {
        const SEED: [u8; 32] = [9u8; 32];
        const TX_KEY: [u8; 32] = [13u8; 32];
        const OUT_IDX: u64 = 0;
        const AMOUNT: u64 = 5_000_000;

        // Recipient wallet: encode its primary address (Edwards view key on the
        // wire), then decode it exactly as `sign_tx` does.
        let recipient_keys = LocalKeys::from_test_seed(SEED);
        let address = recipient_keys
            .keys
            .to_address(Network::Mainnet)
            .encode()
            .expect("encode recipient address");
        let decoded = decode_recipient(&address, Network::Mainnet).expect("decode recipient");

        // Sender-side mapping, exactly as the `sign_tx` payment loop does it.
        let recipient = RecipientKeys::of_address(&decoded).expect("the address's keys");
        let recipient_x25519 = *recipient.view_x25519();
        assert_eq!(
            recipient_x25519, recipient_keys.keys.x25519_pk,
            "the mapped key must equal the wallet's stored montgomery(view_pk)"
        );

        // Positive arm: an output encapsulated to the MAPPED key is recovered
        // by the recipient's view-derived Montgomery secret (the production
        // scanner's derivation).
        let constructed = construct_output(
            TxKey::seeded(TX_KEY)
                .output_positions(usize::try_from(OUT_IDX).unwrap() + 1)
                .at(OUT_IDX)
                .unwrap(),
            &recipient_x25519,
            &decoded.ml_kem_encap_key,
            &decoded.spend_key,
            AMOUNT,
        )
        .expect("construct payment output");
        let recovered = scan_output_recover(
            recipient_keys.keys.view_sk.as_canonical_bytes(),
            recipient_keys.keys.ml_kem_dk.as_canonical_bytes(),
            &constructed.kem_ciphertext_x25519,
            &constructed.kem_ciphertext_ml_kem,
            &constructed.output_key,
            &constructed.commitment,
            &constructed.enc_amount_bytes(),
            constructed.amount_tag(),
            &constructed.enc_label_bytes(),
            constructed.label_tag(),
            constructed.view_tag_prefilter,
            OUT_IDX,
        )
        .expect("recipient must recover the payment output");
        assert_eq!(
            recovered.recovered_spend_key, decoded.spend_key,
            "recovery must yield the recipient's spend key"
        );

        // Negative arm — the bug class this test exists for: encapsulating to
        // the RAW Edwards view-key bytes (interpreted as a Montgomery
        // u-coordinate) produces an output the recipient CANNOT recover.
        let wrong = construct_output(
            TxKey::seeded(TX_KEY)
                .output_positions(usize::try_from(OUT_IDX).unwrap() + 1)
                .at(OUT_IDX)
                .unwrap(),
            &decoded.view_key,
            &decoded.ml_kem_encap_key,
            &decoded.spend_key,
            AMOUNT,
        )
        .expect("construct output to the wrong point (daemon-acceptable)");
        assert!(
            scan_output_recover(
                recipient_keys.keys.view_sk.as_canonical_bytes(),
                recipient_keys.keys.ml_kem_dk.as_canonical_bytes(),
                &wrong.kem_ciphertext_x25519,
                &wrong.kem_ciphertext_ml_kem,
                &wrong.output_key,
                &wrong.commitment,
                &wrong.enc_amount_bytes(),
                wrong.amount_tag(),
                &wrong.enc_label_bytes(),
                wrong.label_tag(),
                wrong.view_tag_prefilter,
                OUT_IDX,
            )
            .is_err(),
            "an output encapsulated to the raw Edwards bytes must NOT be recoverable"
        );
    }

    /// A leftover the ladder does not balance keeps the builder's
    /// insufficient-funds fault. The shortfall stays in the log; the variant
    /// that leaves is the closed one.
    #[test]
    fn a_short_leftover_keeps_the_insufficient_funds_fault() {
        use super::super::traits::key::FeeDirective;
        use shekyl_tx_builder::InternalSignFault;

        let directive = FeeDirective {
            fee_no_change: 700,
            fee_with_change: Some(900),
        };
        let err = KeyEngineError::from(fee_and_change(900, &directive).expect_err("short"));
        assert!(matches!(
            err,
            KeyEngineError::Sign(SignFault::Internal(InternalSignFault::InsufficientFunds))
        ));
    }
}
