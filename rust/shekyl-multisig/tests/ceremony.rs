// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Slice 3's gate (R-8): from member files and slice 1's outputs, an
//! in-process ceremony for 2-of-3 (no holder) and 3-of-5 (one holder),
//! each spending two group outputs, produces a transaction whose every
//! input passes `verify_multisig`, whose FCMP++ proof (SALs included)
//! verifies, and which survives the wire: serialized, parsed back, and
//! verified from the parsed bytes.
//!
//! Each member signs from its own context; files move only as bytes, and
//! every file is imported by the member that receives it.

mod common;

use rand_core::OsRng;

use common::wallet::{
    context, derive, import_into, intent, proposer_inputs, validate, verify_from_the_wire, Wallet,
};
use common::{found_group, pay_group_twice};
use shekyl_multisig::{Cosigner, Holder, MemberFile, Proposer, Responder, ResponderInput};

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// 2-of-3, no holder: files 1, 4, 8, 9.
#[test]
fn two_of_three_spends_two_group_outputs() {
    let (address, files) = found_group(3, 2);
    let mut paid = pay_group_twice(&address, &files);
    let derived = derive(&paid);
    let [a, _, b]: [MemberFile; 3] = files.try_into().ok().unwrap();
    let mut a = Wallet::new(a);
    let mut b = Wallet::new(b);
    let intent = intent(&address, 0, &[0, 2], 2);

    // 1: A proposes.
    let ctx_a = context(&a.file, validate(&a.file, intent.clone()), &paid, &derived);
    let (proposer, proposal) = Proposer::propose(
        ctx_a,
        proposer_inputs(&mut paid, &derived),
        &mut a.store,
        &mut a.live,
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(proposer.responder_file(&mut OsRng).unwrap(), proposal);

    // 4: B approves the intent it received, and responds in one call.
    let at_b = expect!(import_into(&b, &proposal), Proposal);
    let ctx_b = context(
        &b.file,
        validate(&b.file, at_b.body().intent.clone()),
        &paid,
        &derived,
    );
    let response = Responder::respond(
        &ctx_b,
        ResponderInput::Proposal(&at_b),
        &mut b.live,
        &mut OsRng,
    )
    .unwrap();
    assert!(b.store.0.is_empty(), "the responder holds no nonce");

    // 7, 8: A completes, proves and sends the FinalTx.
    let proposer = proposer
        .responder_share(expect!(import_into(&a, &response), ResponderShare))
        .unwrap();
    assert!(proposer.holders_file(&mut OsRng).unwrap().is_none());
    let (proposer, final_tx) = proposer
        .finish(&mut a.store, &mut a.sink, &mut OsRng)
        .unwrap();
    assert!(a.store.0.is_empty(), "the proposer's nonce is consumed");
    assert_eq!(a.sink.persisted.len(), 1);

    // 9: B builds the transaction itself and signs it.
    let hybrid = Cosigner::sign_final_tx(
        &ctx_b,
        &expect!(import_into(&b, &final_tx), FinalTx),
        &mut OsRng,
    )
    .unwrap();

    // 10: A assembles, verifies and releases.
    let tx = proposer
        .hybrid_sig(&expect!(import_into(&a, &hybrid), HybridSig))
        .unwrap()
        .release()
        .unwrap();
    verify_from_the_wire(&tx, &paid);
}

/// 3-of-5, one holder: every file of the table.
#[test]
fn three_of_five_spends_two_group_outputs() {
    let (address, files) = found_group(5, 3);
    let mut paid = pay_group_twice(&address, &files);
    let derived = derive(&paid);
    let mut files: Vec<Option<MemberFile>> = files.into_iter().map(Some).collect();
    let mut wallet = |i: usize| Wallet::new(files[i].take().unwrap());
    let (mut a, mut h, mut b) = (wallet(1), wallet(3), wallet(4));
    let intent = intent(&address, 1, &[1, 3, 4], 4);

    // 1: A proposes; the holder receives it.
    let ctx_a = context(&a.file, validate(&a.file, intent.clone()), &paid, &derived);
    let (proposer, proposal) = Proposer::propose(
        ctx_a,
        proposer_inputs(&mut paid, &derived),
        &mut a.store,
        &mut a.live,
        &mut OsRng,
    )
    .unwrap();

    // 2: the holder commits.
    let at_h = expect!(import_into(&h, &proposal), Proposal);
    let ctx_h = context(
        &h.file,
        validate(&h.file, at_h.body().intent.clone()),
        &paid,
        &derived,
    );
    let (holder, commitment) =
        Holder::commit(ctx_h, &at_h, &mut h.store, &mut h.live, &mut OsRng).unwrap();
    assert_eq!(h.store.0.len(), 1, "the holder holds its nonce");

    // 3: A forwards the proposal and the commitment to B.
    let proposer = proposer
        .commitment(expect!(import_into(&a, &commitment), Commitment))
        .unwrap();
    let to_b = proposer.responder_file(&mut OsRng).unwrap();

    // 4: B responds.
    let at_b = expect!(import_into(&b, &to_b), SigningSet);
    let proposal_at_b = expect!(import_into(&b, &at_b.body().files[0]), Proposal);
    let ctx_b = context(
        &b.file,
        validate(&b.file, proposal_at_b.body().intent.clone()),
        &paid,
        &derived,
    );
    let response = Responder::respond(
        &ctx_b,
        ResponderInput::SigningSet(&at_b),
        &mut b.live,
        &mut OsRng,
    )
    .unwrap();

    // 5: A forwards everything to the holder.
    let proposer = proposer
        .responder_share(expect!(import_into(&a, &response), ResponderShare))
        .unwrap();
    let to_h = proposer.holders_file(&mut OsRng).unwrap().unwrap();

    // 6: the holder signs.
    let share = holder
        .sign(
            &expect!(import_into(&h, &to_h), SigningSet),
            &mut h.store,
            &mut h.sink,
            &mut OsRng,
        )
        .unwrap();
    assert!(h.store.0.is_empty(), "the holder's nonce is consumed");

    // 7, 8: A completes and sends the FinalTx.
    let (proposer, final_tx) = proposer
        .holder_share(expect!(import_into(&a, &share), SignatureShare))
        .unwrap()
        .finish(&mut a.store, &mut a.sink, &mut OsRng)
        .unwrap();

    // 9: B and the holder each build the transaction and sign.
    let ctx_h2 = context(&h.file, validate(&h.file, intent.clone()), &paid, &derived);
    let from_h = Cosigner::sign_final_tx(
        &ctx_h2,
        &expect!(import_into(&h, &final_tx), FinalTx),
        &mut OsRng,
    )
    .unwrap();
    let from_b = Cosigner::sign_final_tx(
        &ctx_b,
        &expect!(import_into(&b, &final_tx), FinalTx),
        &mut OsRng,
    )
    .unwrap();

    // 10: A releases.
    let tx = proposer
        .hybrid_sig(&expect!(import_into(&a, &from_h), HybridSig))
        .unwrap()
        .hybrid_sig(&expect!(import_into(&a, &from_b), HybridSig))
        .unwrap()
        .release()
        .unwrap();
    verify_from_the_wire(&tx, &paid);
}
