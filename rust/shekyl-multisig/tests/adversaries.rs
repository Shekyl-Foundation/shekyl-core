// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The ceremony against each adversary of the brief's §8 table, and a
//! ceremony that survives every member restarting between files.
//!
//! A 3-of-5 group throughout: proposer 1, holder 3, responder 4.

mod common;

use rand_core::OsRng;
use zeroize::Zeroizing;

use common::wallet::{
    context, derive, import_for, intent, try_context, validate, verify_from_the_wire, Derived,
    Live, Sink, Store, PAID,
};
use common::{found_group, pay_group_twice, rebuild_chunks, GroupOutputs, NET};
use shekyl_address::multisig_address::MultisigAddressPayload;
use shekyl_fcmp::frost_sal::{participant, FrostError};
use shekyl_multisig::ceremony::context::ContextError;
use shekyl_multisig::ceremony::files::{Body, Commitment, FinalTx, SignatureShare, SigningSet};
use shekyl_multisig::ceremony::nonce::{ConsumeError, InputInUse};
use shekyl_multisig::ceremony::roles::{Committed, SharesPending};
use shekyl_multisig::intent::SpendIntent;
use shekyl_multisig::{
    import, seal_envelope, CeremonyError, Cosigner, Holder, ImportError, MemberFile, Proposer,
    ProposerInputs, Responder, ResponderInput, SigningContext,
};

/// A 3-of-5 group that owns two outputs, and an intent to spend them.
struct Spend {
    address: MultisigAddressPayload,
    paid: GroupOutputs,
    derived: Derived,
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
    store: Store,
    sink: Sink,
    live: Live,
}

fn setup() -> (Spend, Members, Caps, Caps, Caps) {
    let (address, files) = found_group(5, 3);
    let paid = pay_group_twice(&address, &files);
    let derived = derive(&paid);
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
            derived,
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
        context(file, validate(file, intent), &self.paid, &self.derived)
    }

    fn proposer_inputs(&self) -> ProposerInputs {
        ProposerInputs {
            outputs: vec![(PAID, Zeroizing::new(self.derived.out_mask))],
            leaf_chunks: rebuild_chunks(&self.paid),
        }
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

/// The honest ceremony through step 5.
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
    let (proposer, proposal) = Proposer::propose(
        s.ctx(&m.a),
        s.proposer_inputs(),
        &mut ca.store,
        &mut ca.live,
        &mut OsRng,
    )
    .unwrap();
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
    let (_, proposal) = Proposer::propose(
        s.ctx(&m.a),
        s.proposer_inputs(),
        &mut ca.store,
        &mut ca.live,
        &mut OsRng,
    )
    .unwrap();
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
    let (_, proposal) = Proposer::propose(
        s.ctx(&m.a),
        s.proposer_inputs(),
        &mut ca.store,
        &mut ca.live,
        &mut OsRng,
    )
    .unwrap();
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

/// A malicious proposer equivocates: it proposes the intent twice (two
/// stores) and shows the responder a set built on the second proposal
/// while it continues on the first. The responder's share was made under a
/// different binding than the proposer's, so no SAL completes; every held
/// nonce was used once.
#[test]
fn different_preprocess_sets_give_no_sal_and_no_reused_nonce() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let (proposer, p1) = Proposer::propose(
        s.ctx(&m.a),
        s.proposer_inputs(),
        &mut ca.store,
        &mut ca.live,
        &mut OsRng,
    )
    .unwrap();
    let (_, p2) = Proposer::propose(
        s.ctx(&m.a),
        s.proposer_inputs(),
        &mut Store::default(),
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
            &mut ch.sink,
            &mut OsRng,
        )
        .unwrap();
    assert!(ch.store.0.is_empty());
    assert_eq!(
        ch.sink.persisted.len(),
        1,
        "the holder's nonce was used once"
    );

    let refused = proposer
        .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
        .unwrap()
        .finish(&mut ca.store, &mut ca.sink, &mut OsRng)
        .err();
    assert!(
        matches!(refused, Some(CeremonyError::Signing { .. })),
        "{refused:?}"
    );
    assert!(ca.store.0.is_empty());
    assert_eq!(
        ca.sink.persisted.len(),
        1,
        "the proposer's nonce was used once"
    );
}

/// A malicious proposer's `FinalTx`: proofs that are not over the
/// transaction this member builds from the intent, an edited range proof,
/// an edited membership proof, or a key that is not the signer's. Each is
/// refused before any hybrid signature; the honest file signs.
#[test]
fn a_final_tx_that_is_not_the_intents_is_refused_before_signing() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let share = run
        .holder
        .sign(
            &expect!(import_for(&m.h, &run.to_holder), SigningSet),
            &mut ch.store,
            &mut ch.sink,
            &mut OsRng,
        )
        .unwrap();
    let (_, final_tx) = run
        .proposer
        .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
        .unwrap()
        .finish(&mut ca.store, &mut ca.sink, &mut OsRng)
        .unwrap();
    let honest = expect!(import_for(&m.b, &final_tx), FinalTx);
    let ctx_b = s.ctx(&m.b);
    let edited = |edit: &dyn Fn(&mut FinalTx)| {
        let mut body = FinalTx::decode(&honest.body().encode()).unwrap();
        edit(&mut body);
        expect!(import_for(&m.b, &s.sealed(&m.a, &body)), FinalTx)
    };

    // The member's own transaction pays another output: the proofs are
    // not over it.
    let mut other = derive(&s.paid);
    other.blinds = s.derived.blinds;
    other.seeds = s.derived.seeds;
    let ctx_other = context(&m.b, validate(&m.b, s.intent.clone()), &s.paid, &other);
    assert!(matches!(
        Cosigner::sign_final_tx(&ctx_other, &honest, &mut OsRng),
        Err(CeremonyError::MembershipProof)
    ));
    // Another fee: the member's own transaction carries the intent's fee,
    // or its context does not build; a proof over any other fee is a proof
    // over another transaction, refused as above.
    let mut fee = s.derived.unsigned.clone();
    fee.fee += 1;
    let other_fee = Derived {
        unsigned: fee,
        blinds: s.derived.blinds,
        seeds: s.derived.seeds,
        out_mask: s.derived.out_mask,
    };
    assert!(matches!(
        try_context(&m.b, validate(&m.b, s.intent.clone()), &s.paid, &other_fee),
        Err(ContextError::Fee)
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
            &mut ch.sink,
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
        .finish(&mut ca.store, &mut ca.sink, &mut OsRng)
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
    let (proposer, proposal) = Proposer::propose(
        s.ctx(&m.a),
        s.proposer_inputs(),
        &mut ca.store,
        &mut ca.live,
        &mut OsRng,
    )
    .unwrap();
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
            &mut ch.sink,
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
        s.proposer_inputs(),
        &mut Store::default(),
        &mut Live::default(),
        &mut OsRng,
    )
    .unwrap();
    assert!(matches!(
        proposer2.commitment(expect!(import_for(&m.a, &run.commitment), Commitment)),
        Err(CeremonyError::IntentMismatch)
    ));
}

/// A crash at a holder after it signed: the restarted holder signs again
/// and finds no held nonce. The seed left the store before its use was
/// persisted, and it was persisted once.
#[test]
fn a_held_nonce_signs_once() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let run = through_step_5(&s, &m, &mut ca, &mut ch, &mut cb);
    let set = expect!(import_for(&m.h, &run.to_holder), SigningSet);
    run.holder
        .sign(&set, &mut ch.store, &mut ch.sink, &mut OsRng)
        .unwrap();
    let restarted = Holder::committed(s.ctx(&m.h)).unwrap();
    assert!(matches!(
        restarted.sign(&set, &mut ch.store, &mut ch.sink, &mut OsRng),
        Err(CeremonyError::Consume(ConsumeError::NotHeld))
    ));
    assert_eq!(ch.sink.persisted.len(), 1);
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
        s.proposer_inputs(),
        &mut Store::default(),
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

/// Every member restarts between files: the proposer is rebuilt from its
/// `Proposal` file and replays what it received, the holder is rebuilt as
/// committed, and the second round is stateless. The spend completes.
#[test]
fn every_member_restarting_between_files_still_spends() {
    let (s, m, mut ca, mut ch, mut cb) = setup();
    let (proposer, proposal) = Proposer::propose(
        s.ctx(&m.a),
        s.proposer_inputs(),
        &mut ca.store,
        &mut ca.live,
        &mut OsRng,
    )
    .unwrap();
    drop(proposer);
    let rebuilt = || Proposer::resume(s.ctx(&m.a), s.proposer_inputs(), proposal.clone()).unwrap();

    let at_h = expect!(import_for(&m.h, &proposal), Proposal);
    let (holder, commitment) =
        Holder::commit(s.ctx(&m.h), &at_h, &mut ch.store, &mut ch.live, &mut OsRng).unwrap();
    drop(holder);

    let to_b = rebuilt()
        .commitment(expect!(import_for(&m.a, &commitment), Commitment))
        .unwrap()
        .responder_file(&mut OsRng)
        .unwrap();
    let response = Responder::respond(
        &s.ctx(&m.b),
        ResponderInput::SigningSet(&expect!(import_for(&m.b, &to_b), SigningSet)),
        &mut cb.live,
        &mut OsRng,
    )
    .unwrap();

    let replayed = || {
        rebuilt()
            .commitment(expect!(import_for(&m.a, &commitment), Commitment))
            .unwrap()
            .responder_share(expect!(import_for(&m.a, &response), ResponderShare))
            .unwrap()
    };
    let to_h = replayed().holders_file(&mut OsRng).unwrap().unwrap();
    let share = Holder::committed(s.ctx(&m.h))
        .unwrap()
        .sign(
            &expect!(import_for(&m.h, &to_h), SigningSet),
            &mut ch.store,
            &mut ch.sink,
            &mut OsRng,
        )
        .unwrap();
    let (proposer, final_tx) = replayed()
        .holder_share(expect!(import_for(&m.a, &share), SignatureShare))
        .unwrap()
        .finish(&mut ca.store, &mut ca.sink, &mut OsRng)
        .unwrap();
    let from_h = Cosigner::sign_final_tx(
        &s.ctx(&m.h),
        &expect!(import_for(&m.h, &final_tx), FinalTx),
        &mut OsRng,
    )
    .unwrap();
    let from_b = Cosigner::sign_final_tx(
        &s.ctx(&m.b),
        &expect!(import_for(&m.b, &final_tx), FinalTx),
        &mut OsRng,
    )
    .unwrap();
    let tx = proposer
        .hybrid_sig(&expect!(import_for(&m.a, &from_h), HybridSig))
        .unwrap()
        .hybrid_sig(&expect!(import_for(&m.a, &from_b), HybridSig))
        .unwrap()
        .release()
        .unwrap();
    verify_from_the_wire(&tx, &s.paid);
}
