// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ceremony against each of its adversaries (`PQC_MULTISIG.md` §16.8),
//! the durable nonce write failing, and ceremonies that survive every
//! member restarting between files, the proposer included after it has
//! finished.
//!
//! A 3-of-5 group throughout: proposer 1, holder 3, responder 4.

mod common;

use rand_core::OsRng;

use common::wallet::{
    context, import_for, intent, ledger, validate, verify_from_the_wire, Held, Live,
};
use common::{found_group, pay_group_twice, Paid, NET};
use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_curve_tree::{BlockHeight, ClientError};
use shekyl_fcmp::frost_sal::{participant, FrostError};
use shekyl_multisig::ceremony::context::ContextError;
use shekyl_multisig::ceremony::files::{Body, Commitment, FinalTx, SignatureShare, SigningSet};
use shekyl_multisig::ceremony::nonce::InputInUse;
use shekyl_multisig::ceremony::roles::{Committed, SharesPending};
use shekyl_multisig::intent::SpendIntent;
use shekyl_multisig::{
    import, seal_envelope, CeremonyError, Cosigner, DeriveError, DerivedSpend, GroupOutput,
    GroupOutputLookupError, GroupOutputs, HeldNonceStore, Holder, ImportError, MemberFile,
    Proposer, Responder, ResponderInput, SigningContext,
};
use shekyl_types::{BlockHash, CurveTreeRoot};

/// A 3-of-5 group that owns two outputs, and an intent to spend them.
struct Spend {
    address: MultisigAddressPayload,
    paid: Paid,
    intent: SpendIntent,
}

/// The three signers' member files: proposer 1, holder 3, responder 4.
struct Members {
    a: MemberFile,
    h: MemberFile,
    b: MemberFile,
}

/// One member's injected capabilities.
#[derive(Default)]
struct Caps {
    store: HeldNonceStore,
    live: Live,
}

fn setup() -> (Spend, Members, Caps, Caps, Caps) {
    let (address, files) = found_group(5, 3);
    let paid = pay_group_twice(&address, &files);
    let mut files: Vec<Option<MemberFile>> = files.into_iter().map(Some).collect();
    let mut take = |i: usize| files[i].take().unwrap();
    let members = Members {
        a: take(1),
        h: take(3),
        b: take(4),
    };
    let intent = intent(&address, 1, &[1, 3, 4], 4);
    (
        Spend {
            address,
            paid,
            intent,
        },
        members,
        Caps::default(),
        Caps::default(),
        Caps::default(),
    )
}

impl Spend {
    fn ctx<'w>(&self, file: &'w MemberFile) -> SigningContext<'w> {
        self.ctx_for(file, self.intent.clone())
    }

    fn ctx_for<'w>(&self, file: &'w MemberFile, intent: SpendIntent) -> SigningContext<'w> {
        context(file, validate(file, intent), &self.paid)
    }

    /// `body` as a file for this intent, sealed by `from`.
    fn sealed<B: Body>(&self, from: &MemberFile, body: &B) -> Vec<u8> {
        seal_envelope(
            from,
            &NET,
            &self.intent.intent_hash().unwrap(),
            B::TYPE,
            &body.encode(),
            &mut OsRng,
        )
        .unwrap()
    }
}

/// The honest ceremony through step 5, with the holder's commitment and
/// the set the proposer forwards to it.
struct ThroughStep5<'w> {
    proposer: Proposer<'w, SharesPending>,
    holder: Holder<'w, Committed>,
    commitment: Vec<u8>,
    to_holder: Vec<u8>,
}

fn through_step_5<'w>(
    s: &Spend,
    m: &'w Members,
    ca: &mut Caps,
    ch: &mut Caps,
    cb: &mut Caps,
) -> ThroughStep5<'w> {
    let (proposer, proposal) =
        Proposer::propose(s.ctx(&m.a), &mut ca.store, &mut ca.live, &mut OsRng).unwrap();
    let at_h = expect!(import_for(&m.h, &proposal), Proposal);
    let (holder, commitment) =
        Holder::commit(s.ctx(&m.h), &at_h, &mut ch.store, &mut ch.live, &mut OsRng).unwrap();
    let proposer = proposer
        .commitment(expect!(import_for(&m.a, &commitment), Commitment))
        .unwrap();
    let to_b = proposer.responder_file(&mut OsRng).unwrap();
    let response = Responder::respond(
        &s.ctx(&m.b),
        ResponderInput::SigningSet(&expect!(import_for(&m.b, &to_b), SigningSet)),
        &mut cb.live,
        &mut OsRng,
    )
    .unwrap();
    let proposer = proposer
        .responder_share(expect!(import_for(&m.a, &response), ResponderShare))
        .unwrap();
    let to_holder = proposer.holders_file(&mut OsRng).unwrap().unwrap();
    ThroughStep5 {
        proposer,
        holder,
        commitment,
        to_holder,
    }
}

// ---------------------------------------------------------------------------
// §8
// ---------------------------------------------------------------------------

/// A compromised member writes a `Proposal` under its own name: the file
/// opens, but it is not from the intent's proposer. One naming the
/// proposer as its sender is refused by `import` at the envelope
/// signature (`envelope::tests::a_member_cannot_write_a_file_as_another_member`,
/// in-crate: forging needs the plaintext codec, which is private).
#[test]
fn a_proposal_not_from_the_proposer_is_refused() {
    let (s, m, mut ca, _, _) = setup();
    let (_, proposal) =
        Proposer::propose(s.ctx(&m.a), &mut ca.store, &mut ca.live, &mut OsRng).unwrap();
    let honest = expect!(import_for(&m.h, &proposal), Proposal);
    let forged = s.sealed(&m.h, honest.body());
    assert!(matches!(
        import(&[&m.b], &NET, &forged),
        Err(ImportError::ProposalSender)
    ));
}

/// A malicious proposer forwards a `Commitment` it wrote itself inside the
/// responder's `SigningSet`: it opens under the proposer's own signature,
/// and the proposer is not a holder.
#[test]
fn a_forged_commitment_in_a_signing_set_is_refused() {
    let (s, m, mut ca, _, mut cb) = setup();
    let (_, proposal) =
        Proposer::propose(s.ctx(&m.a), &mut ca.store, &mut ca.live, &mut OsRng).unwrap();
    let at_h = expect!(import_for(&m.h, &proposal), Proposal);
    let forged = s.sealed(
        &m.a,
        &Commitment {
            rounds: at_h.body().rounds.clone(),
        },
    );
    let set = s.sealed(
        &m.a,
        &SigningSet {
            files: vec![proposal, forged],
        },
    );
    assert!(matches!(
        Responder::respond(
            &s.ctx(&m.b),
            ResponderInput::SigningSet(&expect!(import_for(&m.b, &set), SigningSet)),
            &mut cb.live,
            &mut OsRng,
        ),
        Err(CeremonyError::Sender { sender: 1 })
    ));
}

/// A malicious proposer leaves a holder's `Commitment` out of the set it
/// shows the responder: the set is not exactly the other signers, and the
/// responder signs nothing.
#[test]
fn a_signing_set_without_every_signer_is_refused() {
    let (s, m, mut ca, _, mut cb) = setup();
    let (_, proposal) =
        Proposer::propose(s.ctx(&m.a), &mut ca.store, &mut ca.live, &mut OsRng).unwrap();
    let set = s.sealed(
        &m.a,
        &SigningSet {
            files: vec![proposal],
        },
    );
    assert!(matches!(
        Responder::respond(
            &s.ctx(&m.b),
            ResponderInput::SigningSet(&expect!(import_for(&m.b, &set), SigningSet)),
            &mut cb.live,
            &mut OsRng,
        ),
        Err(CeremonyError::SigningSetContents)
    ));
}

/// A malicious proposer equivocates: it proposes the intent twice (two
/// stores) and shows the responder a set built on the second proposal
/// while it continues on the first. The responder's share was made under a
/// different binding than the proposer's, so no SAL completes; every held
/// nonce was used once.
#[test]
fn different_preprocess_sets_give_no_sal_and_no_reused_nonce() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let (proposer, p1) =
        Proposer::propose(s.ctx(&m.a), &mut ca.store, &mut ca.live, &mut OsRng).unwrap();
    let (_, p2) = Proposer::propose(
        s.ctx(&m.a),
        &mut HeldNonceStore::new(),
        &mut Live::default(),
        &mut OsRng,
    )
    .unwrap();
    let at_h = expect!(import_for(&m.h, &p1), Proposal);
    let (holder, c) =
        Holder::commit(s.ctx(&m.h), &at_h, &mut ch.store, &mut ch.live, &mut OsRng).unwrap();

    let to_b = s.sealed(
        &m.a,
        &SigningSet {
            files: vec![p2, c.clone()],
        },
    );
    let response = Responder::respond(
        &s.ctx(&m.b),
        ResponderInput::SigningSet(&expect!(import_for(&m.b, &to_b), SigningSet)),
        &mut cb.live,
        &mut OsRng,
    )
    .unwrap();

    let proposer = proposer
        .commitment(expect!(import_for(&m.a, &c), Commitment))
        .unwrap()
        .responder_share(expect!(import_for(&m.a, &response), ResponderShare))
        .unwrap();
    let to_h = proposer.holders_file(&mut OsRng).unwrap().unwrap();
    let share = holder
        .sign(
            &expect!(import_for(&m.h, &to_h), SigningSet),
            &mut ch.store,
            &mut OsRng,
        )
        .unwrap();
    let hash = s.intent.intent_hash().unwrap();
    assert!(!ch.store.holds(&hash), "the holder's nonce was used once");

    let refused = proposer
        .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
        .unwrap()
        .finish(&mut ca.store, &mut OsRng)
        .err();
    assert!(
        matches!(refused, Some(CeremonyError::Signing { .. })),
        "{refused:?}"
    );
    assert!(!ca.store.holds(&hash), "the proposer's nonce was used once");
}

/// A malicious proposer's `FinalTx`: proofs that are not over the
/// transaction this member builds from the intent, an edited range proof,
/// an edited membership proof, or a key that is not the signer's. Each is
/// refused before any hybrid signature; the honest file signs. The fee and
/// the reference block are the intent's in every member's own transaction
/// (`SigningContext` reads them from the intent), so no file can move
/// them; `verify_from_the_wire` checks both on every released spend.
#[test]
fn a_final_tx_that_is_not_the_intents_is_refused_before_signing() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let share = run
        .holder
        .sign(
            &expect!(import_for(&m.h, &run.to_holder), SigningSet),
            &mut ch.store,
            &mut OsRng,
        )
        .unwrap();
    let (_, final_tx) = run
        .proposer
        .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
        .unwrap()
        .finish(&mut ca.store, &mut OsRng)
        .unwrap();
    let honest = expect!(import_for(&m.b, &final_tx), FinalTx);
    let ctx_b = s.ctx(&m.b);
    let edited = |edit: &dyn Fn(&mut FinalTx)| {
        let mut body = FinalTx::decode(&honest.body().encode()).unwrap();
        edit(&mut body);
        expect!(import_for(&m.b, &s.sealed(&m.a, &body)), FinalTx)
    };

    // A member whose ledger's paths are to another tree derives a context
    // under that root: the proposer's honest proof is not over it.
    let mut elsewhere = ledger(&m.b, &s.paid);
    for output in &mut elsewhere.0 {
        output.1.tree.tree_root = CurveTreeRoot::EMPTY;
    }
    let other = DerivedSpend::derive(
        validate(&m.b, s.intent.clone()),
        &elsewhere,
        &m.b.group_key(),
        NET,
    )
    .unwrap();
    let ctx_other = SigningContext::new(&m.b, other).unwrap();
    assert!(matches!(
        Cosigner::sign_final_tx(&ctx_other, &honest, &mut OsRng),
        Err(CeremonyError::MembershipProof)
    ));
    assert!(matches!(
        Cosigner::sign_final_tx(&ctx_b, &edited(&|f| f.range_proof[40] ^= 1), &mut OsRng),
        Err(CeremonyError::RangeProof)
    ));
    assert!(matches!(
        Cosigner::sign_final_tx(&ctx_b, &edited(&|f| f.fcmp_proof[100] ^= 1), &mut OsRng),
        Err(CeremonyError::MembershipProof)
    ));
    assert!(matches!(
        Cosigner::sign_final_tx(
            &ctx_b,
            &edited(&|f| f.keys[0][2] = f.keys[0][1].clone()),
            &mut OsRng
        ),
        Err(CeremonyError::KeyHash {
            member: 4,
            input: 0
        })
    ));
    assert!(Cosigner::sign_final_tx(&ctx_b, &honest, &mut OsRng).is_ok());
}

/// A malicious holder's bad share: `complete` names that holder.
#[test]
fn a_bad_share_is_named_by_its_signer() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let share = run
        .holder
        .sign(
            &expect!(import_for(&m.h, &run.to_holder), SigningSet),
            &mut ch.store,
            &mut OsRng,
        )
        .unwrap();
    let mut shares = expect!(import_for(&m.a, &share), SignatureShare)
        .body()
        .shares
        .clone();
    shares[1] = [1; 32];
    let bad = s.sealed(&m.h, &SignatureShare { shares });
    let refused = run
        .proposer
        .holder_share(expect!(import_for(&m.a, &bad), SignatureShare))
        .unwrap()
        .finish(&mut ca.store, &mut OsRng)
        .err();
    assert!(
        matches!(
            refused,
            Some(CeremonyError::Signing {
                input: 1,
                source: FrostError::InvalidShare(p)
            }) if p == participant(3)
        ),
        "{refused:?}"
    );
}

/// A malicious cosigner sends a per-output key that is not its own:
/// refused on receipt, in round 1.
#[test]
fn a_key_that_does_not_match_its_hash_is_refused_in_round_one() {
    let (s, m, mut ca, mut ch, _) = setup();
    let (proposer, proposal) =
        Proposer::propose(s.ctx(&m.a), &mut ca.store, &mut ca.live, &mut OsRng).unwrap();
    let at_h = expect!(import_for(&m.h, &proposal), Proposal);
    let (_, commitment) =
        Holder::commit(s.ctx(&m.h), &at_h, &mut ch.store, &mut ch.live, &mut OsRng).unwrap();
    let mut rounds = expect!(import_for(&m.a, &commitment), Commitment)
        .body()
        .rounds
        .clone();
    rounds[0].key = at_h.body().rounds[0].key.clone();
    let lying = s.sealed(&m.h, &Commitment { rounds });
    assert!(matches!(
        proposer.commitment(expect!(import_for(&m.a, &lying), Commitment)),
        Err(CeremonyError::KeyHash {
            member: 3,
            input: 0
        })
    ));
}

/// A file replayed in one phase is a duplicate; a file of one intent fed
/// into another intent's ceremony is refused by its intent hash.
#[test]
fn a_replayed_file_is_refused() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let share = run
        .holder
        .sign(
            &expect!(import_for(&m.h, &run.to_holder), SigningSet),
            &mut ch.store,
            &mut OsRng,
        )
        .unwrap();
    let proposer = run
        .proposer
        .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
        .unwrap();
    assert!(matches!(
        proposer.holder_share(expect!(import_for(&m.a, &share), SignatureShare)),
        Err(CeremonyError::Duplicate { member: 3 })
    ));

    let second = intent(&s.address, 1, &[1, 3, 4], 4);
    let (proposer2, _) = Proposer::propose(
        s.ctx_for(&m.a, second),
        &mut HeldNonceStore::new(),
        &mut Live::default(),
        &mut OsRng,
    )
    .unwrap();
    assert!(matches!(
        proposer2.commitment(expect!(import_for(&m.a, &run.commitment), Commitment)),
        Err(CeremonyError::IntentMismatch)
    ));
}

/// A held nonce signs once: signing takes it out of the store, so the
/// holder that signed holds nothing more for the intent, and the holder
/// type that signed is consumed with it.
#[test]
fn a_held_nonce_signs_once() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let hash = s.intent.intent_hash().unwrap();
    assert!(ch.store.holds(&hash));
    let set = expect!(import_for(&m.h, &run.to_holder), SigningSet);
    run.holder.sign(&set, &mut ch.store, &mut OsRng).unwrap();
    assert!(!ch.store.holds(&hash), "the nonce left the store to sign");
}

/// A member in two ceremonies: a second intent spending the same inputs
/// is refused at commit.
#[test]
fn a_second_intent_on_a_live_input_is_refused() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let _run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let second = intent(&s.address, 1, &[1, 3, 4], 4);
    let (_, proposal) = Proposer::propose(
        s.ctx_for(&m.a, second.clone()),
        &mut HeldNonceStore::new(),
        &mut Live::default(),
        &mut OsRng,
    )
    .unwrap();
    let at_h = expect!(import_for(&m.h, &proposal), Proposal);
    assert!(matches!(
        Holder::commit(
            s.ctx_for(&m.h, second),
            &at_h,
            &mut ch.store,
            &mut ch.live,
            &mut OsRng
        ),
        Err(CeremonyError::InputInUse(InputInUse { input: 10 }))
    ));
}

// ---------------------------------------------------------------------------
// Restarts
// ---------------------------------------------------------------------------

/// A holder whose wallet closes between its commit and its share forfeits
/// its part (R-20): its nonce was in the wallet's memory only, and nothing
/// rebuilds a committed holder. The proposer cannot finish without the
/// holder's share. Once the old intent's reservations are abandoned, a new
/// intent completes the spend.
#[test]
fn a_holder_closing_between_commit_and_share_forfeits_its_ceremony() {
    let (mut s, m, mut ca, mut ch, mut cb) = setup();
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let hash = s.intent.intent_hash().unwrap();
    drop(run.holder);
    ch.store = HeldNonceStore::new();
    assert!(!ch.store.holds(&hash), "a closed wallet holds no nonce");
    assert!(matches!(
        run.proposer.finish(&mut ca.store, &mut OsRng).err(),
        Some(CeremonyError::Incomplete)
    ));

    s.intent = intent(&s.address, 1, &[1, 3, 4], 4);
    let (mut ca, mut ch, mut cb) = (Caps::default(), Caps::default(), Caps::default());
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let share = run
        .holder
        .sign(
            &expect!(import_for(&m.h, &run.to_holder), SigningSet),
            &mut ch.store,
            &mut OsRng,
        )
        .unwrap();
    let (proposer, final_tx) = run
        .proposer
        .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
        .unwrap()
        .finish(&mut ca.store, &mut OsRng)
        .unwrap();
    let mut proposer = proposer;
    for cosigner in [&m.h, &m.b] {
        let signed = Cosigner::sign_final_tx(
            &s.ctx(cosigner),
            &expect!(import_for(cosigner, &final_tx), FinalTx),
            &mut OsRng,
        )
        .unwrap();
        proposer = proposer
            .hybrid_sig(expect!(import_for(&m.a, &signed), HybridSig))
            .unwrap();
    }
    verify_from_the_wire(&proposer.release().unwrap(), &s.paid);
}

/// A proposer signs only from the store that holds its nonce: a wallet
/// reopened with an empty store has nothing to sign from, and refuses by
/// name before any SAL or proof.
#[test]
fn a_proposer_signs_only_from_the_store_holding_its_nonce() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let share = run
        .holder
        .sign(
            &expect!(import_for(&m.h, &run.to_holder), SigningSet),
            &mut ch.store,
            &mut OsRng,
        )
        .unwrap();
    assert!(matches!(
        run.proposer
            .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
            .unwrap()
            .finish(&mut HeldNonceStore::new(), &mut OsRng)
            .err(),
        Some(CeremonyError::NotHeld(_))
    ));
}

/// The proposer restarts after it has finished: it is rebuilt from the
/// `FinalTx` it sent, re-checks and re-signs that transaction, replays the
/// hybrid signatures it received, and releases. Once straight after
/// finishing, once after one signature had arrived.
#[test]
fn a_proposer_restarting_after_finish_still_releases() {
    for received_before_restart in 0..=1 {
        let (s, m, mut ca, mut ch, mut cb) = setup();
        let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
        let share = run
            .holder
            .sign(
                &expect!(import_for(&m.h, &run.to_holder), SigningSet),
                &mut ch.store,
                &mut OsRng,
            )
            .unwrap();
        let (mut proposer, final_tx) = run
            .proposer
            .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
            .unwrap()
            .finish(&mut ca.store, &mut OsRng)
            .unwrap();
        let signed: Vec<Vec<u8>> = [&m.h, &m.b]
            .into_iter()
            .map(|cosigner| {
                Cosigner::sign_final_tx(
                    &s.ctx(cosigner),
                    &expect!(import_for(cosigner, &final_tx), FinalTx),
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect();
        for file in &signed[..received_before_restart] {
            proposer = proposer
                .hybrid_sig(expect!(import_for(&m.a, file), HybridSig))
                .unwrap();
        }
        drop(proposer);

        let mut proposer = Proposer::resume_after_finish(s.ctx(&m.a), &final_tx).unwrap();
        for file in &signed {
            proposer = proposer
                .hybrid_sig(expect!(import_for(&m.a, file), HybridSig))
                .unwrap();
        }
        verify_from_the_wire(&proposer.release().unwrap(), &s.paid);
    }
}

/// The proposer is rebuilt as finished only from its own `FinalTx`: not
/// from its `Proposal`, and not from a `FinalTx` another member wrote.
#[test]
fn a_proposer_resumes_after_finish_only_from_its_own_final_tx() {
    let (s, m, mut ca, _, _) = setup();
    let (_, proposal) =
        Proposer::propose(s.ctx(&m.a), &mut ca.store, &mut ca.live, &mut OsRng).unwrap();
    assert!(matches!(
        Proposer::resume_after_finish(s.ctx(&m.a), &proposal).err(),
        Some(CeremonyError::FileType)
    ));
    let key = expect!(import_for(&m.a, &proposal), Proposal).body().rounds[0]
        .key
        .clone();
    let forged = s.sealed(
        &m.h,
        &FinalTx {
            proposal_file: proposal,
            keys: vec![vec![key; 3]; 2],
            fcmp_proof: Vec::new(),
            range_proof: Vec::new(),
        },
    );
    assert!(matches!(
        Proposer::resume_after_finish(s.ctx(&m.a), &forged).err(),
        Some(CeremonyError::Sender { sender: 3 })
    ));
}

// ---------------------------------------------------------------------------
// The context
// ---------------------------------------------------------------------------

/// A reference tree with a layer count no spend proves under builds no
/// context.
#[test]
fn a_context_needs_a_layer_count_a_spend_proves_under() {
    let (s, m, ..) = setup();
    for layers in [0, 1, shekyl_fcmp::MAX_TREE_DEPTH + 1] {
        let mut held = ledger(&m.b, &s.paid);
        for output in &mut held.0 {
            output.1.tree.tree_depth = layers;
        }
        let derived = DerivedSpend::derive(
            validate(&m.b, s.intent.clone()),
            &held,
            &m.b.group_key(),
            NET,
        )
        .unwrap();
        assert!(matches!(
            SigningContext::new(&m.b, derived),
            Err(ContextError::TreeLayers { layers: refused }) if refused == layers
        ));
    }
}

/// A member's inputs are put in the transaction's order whatever order its
/// ledger hands them over in: the spend derived from them reversed signs
/// the same message.
#[test]
fn a_derivation_orders_its_inputs_by_key_image() {
    let (s, m, ..) = setup();
    let in_order = s.ctx(&m.b);
    let mut reversed = ledger(&m.b, &s.paid);
    reversed.0.reverse();
    let derived = DerivedSpend::derive(
        validate(&m.b, s.intent.clone()),
        &reversed,
        &m.b.group_key(),
        NET,
    )
    .unwrap();
    let from_reversed = SigningContext::new(&m.b, derived).unwrap();
    assert_eq!(in_order.tx_signable(), from_reversed.tx_signable());
}

/// A derivation looks each of the intent's inputs up in the member's
/// ledger and re-derives its secrets from the record's `0x06` ciphertext.
/// A ledger holding more than the intent spends derives; a record that is
/// missing, or that names a key image or leaf its secrets do not derive,
/// or two records of one output, derive nothing, each refusal by name.
#[test]
fn a_derivation_spends_the_intents_inputs_as_their_secrets_derive() {
    let (s, m, ..) = setup();
    let derive_from = |edit: &dyn Fn(&mut Vec<Held>)| {
        let mut held = ledger(&m.b, &s.paid);
        edit(&mut held.0);
        DerivedSpend::derive(
            validate(&m.b, s.intent.clone()),
            &held,
            &m.b.group_key(),
            NET,
        )
        .err()
    };
    assert!(derive_from(&|l| {
        let mut unspent = l[0].clone();
        unspent.0.global_index = 99;
        l.push(unspent);
    })
    .is_none());
    assert!(matches!(
        derive_from(&|l| {
            l.pop();
        }),
        Some(DeriveError::MissingInput { .. })
    ));
    // A ledger that holds the output but cannot assemble its path to the
    // intent's reference block: refused by name, not as a missing input.
    struct Unassembled(common::wallet::Ledger);
    impl GroupOutputs for Unassembled {
        fn output(
            &self,
            global_index: u64,
            reference_block: &BlockHash,
        ) -> Result<GroupOutput, GroupOutputLookupError> {
            self.0.output(global_index, reference_block)?;
            Err(GroupOutputLookupError::NoPath(ClientError::RootMismatch {
                height: BlockHeight::from_raw(1),
                expected: CurveTreeRoot::EMPTY,
                got: CurveTreeRoot::from_bytes([1; 32]),
            }))
        }
    }
    assert!(matches!(
        DerivedSpend::derive(
            validate(&m.b, s.intent.clone()),
            &Unassembled(ledger(&m.b, &s.paid)),
            &m.b.group_key(),
            NET,
        )
        .err(),
        Some(DeriveError::NoPath { .. })
    ));
    assert!(matches!(
        derive_from(&|l| l[0].0.key_image = l[1].0.key_image),
        Some(DeriveError::KeyImage { .. })
    ));
    assert!(matches!(
        derive_from(&|l| l[0].0.leaf_point = l[1].0.leaf_point),
        Some(DeriveError::Leaf { .. })
    ));
    // A record whose commitment is another coin's: it does not open to
    // the mask this input's secrets derive at its stated amount (R-27).
    assert!(matches!(
        derive_from(&|l| l[0].0.commitment = l[1].0.commitment),
        Some(DeriveError::InputCommitment { .. })
    ));
    assert!(matches!(
        derive_from(&|l| {
            l[0].0.source_x25519_ct = l[1].0.source_x25519_ct;
            l[0].0.source_ml_kem_ct = l[1].0.source_ml_kem_ct.clone();
        }),
        Some(DeriveError::KeyImage { .. })
    ));
    // A path to another tree than the other input's, or one whose leaf
    // chunk does not hold the output. Every path is assembled to the
    // intent's reference block (R-26), so none can name another block.
    assert!(matches!(
        derive_from(&|l| l[1].1.tree.tree_root = CurveTreeRoot::EMPTY),
        Some(DeriveError::Tree { .. })
    ));
    assert!(matches!(
        derive_from(&|l| {
            let spent = l[0].0.output_key;
            l[0].1
                .leaf_chunk
                .retain(|leaf| leaf.output_key.to_bytes() != spent);
        }),
        Some(DeriveError::Path { .. })
    ));
    // One output recorded at both of the intent's global indices (an
    // output key paid twice): both records derive, to one key image.
    assert!(matches!(
        derive_from(&|l| {
            let global_index = l[1].0.global_index;
            l[1] = l[0].clone();
            l[1].0.global_index = global_index;
        }),
        Some(DeriveError::DuplicateKeyImage)
    ));
}
