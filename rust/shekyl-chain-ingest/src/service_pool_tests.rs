// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool as a consumer of the connector, through the ingest service
//! (the brief's c6; `DRS_X_STORE_FLIP.md` DX-Q5, PR2-Q4): the tip
//! follower's reconcile, a switch's returns and an alternative block's
//! bodies through the door, and a compact block resolved from what the
//! pool shows. The spends are real, over a scenario chain the service
//! receives through its door.

use std::sync::{Arc, Mutex};

use shekyl_chain_rules::AdmissionPolicy;
use shekyl_chain_store::store::{ChainStore, SnapshotView};
use shekyl_hash_budget::Budget;
use shekyl_mempool::{Admission, Pool};
use shekyl_types::{TxHash, UnixSeconds};
use shekyl_wire::Transaction;

use super::service_tests::{arrival, offer_all, Gated};
use super::{Follow, PoolWiring, Reply, Service, ServiceConfig};
use crate::pool_door_tests::{matured, paying_the_floor, AT};
use crate::scenario::{Mined, Scenario, RULES};
use crate::test_support::{cleanup, open_store, tmp};

/// A service over a fresh store with a pool wired, and the pool.
struct Pooled {
    service: Service<Gated>,
    pool: Arc<Mutex<Pool>>,
    store_path: std::path::PathBuf,
    pool_path: std::path::PathBuf,
}

impl Pooled {
    fn start(name: &str) -> Self {
        let store_path = tmp(name);
        let pool_path = tmp(&format!("{name}-pool"));
        let store = Arc::new(open_store(&store_path));
        let pool = {
            let snap = store.begin_read().expect("read");
            let view = SnapshotView::new(&snap);
            let rule_set = RULES.in_force(shekyl_types::BlockHeight::ZERO);
            let (pool, _, _) = Pool::open(
                &pool_path,
                UnixSeconds::from_raw(1),
                &view,
                &rule_set,
                &AdmissionPolicy::GENESIS,
            )
            .expect("open");
            Arc::new(Mutex::new(pool))
        };
        let service = Service::start(
            store,
            RULES,
            Arc::new(Gated::new()),
            ServiceConfig::default(),
            Budget::of_host(),
            Follow {
                miner: None,
                pool: Some(PoolWiring {
                    pool: Arc::clone(&pool),
                    policy: AdmissionPolicy::GENESIS,
                    wall: Arc::new(|| UnixSeconds::from_raw(10)),
                }),
            },
        );
        Self {
            service,
            pool,
            store_path,
            pool_path,
        }
    }

    /// Run `f` over the pool and the chain the service's store holds now.
    fn on_pool<R>(
        &self,
        f: impl FnOnce(&mut Pool, &SnapshotView<'_>, &shekyl_chain_rules::RuleSet) -> R,
    ) -> R {
        let store: &ChainStore = &self.service.shared.store;
        let snap = store.begin_read().expect("read");
        let view = SnapshotView::new(&snap);
        let connecting = shekyl_chain_rules::Tip::connecting_height(
            shekyl_chain_rules::HeaderView::tip(&view)
                .expect("tip")
                .as_ref(),
        );
        let mut pool = self.pool.lock().expect("pool");
        f(&mut pool, &view, &RULES.in_force(connecting))
    }

    /// Admit `tx` as a relayed arrival: held, not yet public.
    fn admit(&self, tx: &Transaction) {
        let admitted = self.on_pool(|pool, view, rule_set| {
            pool.admit(
                tx.clone(),
                UnixSeconds::from_raw(10),
                view,
                rule_set,
                &AdmissionPolicy::GENESIS,
            )
            .expect("judged")
        });
        assert!(
            matches!(admitted, Admission::Admitted { .. }),
            "{admitted:?}"
        );
    }

    /// The pool's record of `txid`: held, and public.
    fn record(&self, txid: &TxHash) -> Option<bool> {
        self.on_pool(|pool, _, _| pool.relay_view().record(txid).map(|r| r.public))
    }

    /// Wait until the tip follower has acted on the latest publication.
    async fn followed(&self) {
        let mut tips = self.service.watch_tip().await.expect("watch");
        let seq = tips.borrow_and_update().seq;
        self.service
            .followed()
            .wait_for(|at| *at >= seq)
            .await
            .expect("following");
    }

    async fn stop(self) {
        self.service.stop().await.expect("stops");
        drop(self.pool);
        cleanup(&self.store_path);
        cleanup(&self.pool_path);
    }
}

/// `mined` as a compact arrival: the block and none of its bodies.
fn compact(tag: u64, mined: &Mined) -> super::Arrival {
    super::Arrival {
        bodies: Vec::new(),
        ..arrival(tag, 1, mined)
    }
}

/// After a committed connect the tip follower reconciles the pool: a
/// transaction the block mined leaves it.
#[tokio::test(flavor = "multi_thread")]
async fn a_mined_transaction_leaves_the_pool_on_connect() {
    let (mut x, prefix) = matured("svc-pool-mined-x").await;
    let tx = paying_the_floor(&mut x, &prefix, 0).await;
    let txid = tx.txid_parts().hash;
    let pooled = Pooled::start("svc-pool-mined");
    offer_all(&pooled.service.door(), 1, &prefix).await;
    pooled.admit(&tx);
    assert_eq!(pooled.record(&txid), Some(false), "held, not yet public");
    let block = x.mine_listing(vec![tx]).await.expect("connects");
    let replies = offer_all(&pooled.service.door(), 1, std::slice::from_ref(&block)).await;
    assert!(matches!(replies[0], Reply::Connected { .. }), "{replies:?}");
    pooled.followed().await;
    assert_eq!(pooled.record(&txid), None, "mined: it left the pool");
    pooled.stop().await;
    x.close().await;
}

/// A switch's returns run the pool's door against the chain it left: a
/// transaction the demoted block listed comes back, public (a block
/// carried it).
#[tokio::test(flavor = "multi_thread")]
async fn a_switchs_returns_run_the_door() {
    let (mut x, prefix) = matured("svc-pool-returns-x").await;
    let mut y = Scenario::open("svc-pool-returns-y");
    y.mine(AT).await;
    let tx = paying_the_floor(&mut x, &prefix, 0).await;
    let txid = tx.txid_parts().hash;
    let demoted = x.mine_listing(vec![tx]).await.expect("connects");
    y.idle();
    let heavier = y.mine(2).await;
    let pooled = Pooled::start("svc-pool-returns");
    let door = pooled.service.door();
    offer_all(&door, 1, &prefix).await;
    offer_all(&door, 1, std::slice::from_ref(&demoted)).await;
    let replies = offer_all(&door, 2, &heavier).await;
    assert!(matches!(replies[0], Reply::Held { .. }), "{replies:?}");
    assert!(matches!(replies[1], Reply::Switched { .. }), "{replies:?}");
    pooled.followed().await;
    assert_eq!(pooled.record(&txid), Some(true), "returned, and public");
    pooled.stop().await;
    x.close().await;
    y.close().await;
}

/// A compact block is resolved from the bodies the pool shows, and only
/// those (PR2-Q4): a listed transaction the pool holds in its stem phase
/// counts as missing and is asked for; once it is public the same compact
/// block resolves and connects.
#[tokio::test(flavor = "multi_thread")]
async fn a_compact_block_asks_for_a_stem_body_and_resolves_a_shown_one() {
    let (mut x, prefix) = matured("svc-pool-compact-x").await;
    let tx = paying_the_floor(&mut x, &prefix, 0).await;
    let txid = tx.txid_parts().hash;
    let block = x.mine_listing(vec![tx.clone()]).await.expect("connects");
    let pooled = Pooled::start("svc-pool-compact");
    let door = pooled.service.door();
    offer_all(&door, 1, &prefix).await;
    pooled.admit(&tx);
    let asked = door.offer(compact(1, &block)).expect("room").reply().await;
    assert_eq!(
        asked.reply,
        Reply::MissingBodies { indices: vec![0] },
        "a stem body is not resolved from the pool"
    );
    let fluffed = pooled.on_pool(|pool, _, _| pool.fluffed(&txid).expect("fluffed"));
    assert!(fluffed, "now public");
    let resolved = door.offer(compact(2, &block)).expect("room").reply().await;
    assert!(
        matches!(resolved.reply, Reply::Connected { .. }),
        "the shown body resolves it: {resolved:?}"
    );
    pooled.stop().await;
    x.close().await;
}

/// An alternative block's bodies go to the pool's door only after it was
/// stored — after the cheap tier and its proof-of-work and AL1 — never for
/// a block refused before it: a stored one makes its body public in the
/// pool, a refused one leaves the pool as it was.
#[tokio::test(flavor = "multi_thread")]
async fn an_alternative_blocks_bodies_are_supplemented_only_once_it_is_stored() {
    let (mut x, prefix) = matured("svc-pool-supplement-x").await;
    let mut y = Scenario::open("svc-pool-supplement-y");
    y.mine(AT).await;
    let carried = paying_the_floor(&mut x, &prefix, 0).await;
    let refused_body = paying_the_floor(&mut x, &prefix, 1).await;
    // The main chain's block at AT lists nothing; the alternative at AT
    // carries `carried`; a second alternative at AT carries `refused_body`
    // and is refused before its proof-of-work (CEN-B2).
    let main = x.mine(1).await;
    y.idle();
    let alt = y
        .mine_listing(vec![carried.clone()])
        .await
        .expect("connects");
    let mut z = Scenario::open("svc-pool-supplement-z");
    z.mine(AT).await;
    z.idle();
    z.idle();
    let refused = z
        .mine_listing(vec![refused_body.clone()])
        .await
        .expect("connects");
    let pooled = Pooled::start("svc-pool-supplement");
    let door = pooled.service.door();
    offer_all(&door, 1, &prefix).await;
    offer_all(&door, 1, &main).await;
    let held = door
        .offer(arrival(10, 2, &alt))
        .expect("room")
        .reply()
        .await;
    assert!(matches!(held.reply, Reply::Held { .. }), "{held:?}");
    assert_eq!(
        pooled.record(&carried.txid_parts().hash),
        Some(true),
        "a stored alternative's body is in the pool, public"
    );
    let mut bad = refused.template.block.clone();
    bad.header.minor_version = 1;
    let refusal = door
        .offer(super::Arrival {
            block: bad.serialize(),
            ..arrival(11, 3, &refused)
        })
        .expect("room")
        .reply()
        .await;
    assert!(matches!(refusal.reply, Reply::Refused(_)), "{refusal:?}");
    assert_eq!(
        pooled.record(&refused_body.txid_parts().hash),
        None,
        "a refused block's body is not offered"
    );
    pooled.stop().await;
    for s in [x, y, z] {
        s.close().await;
    }
}

/// A carried body the tip moved under is judged again against the new
/// chain, never answered as a fault (the review of #1102); any other pool
/// fault is one.
#[tokio::test]
async fn a_body_the_tip_moved_under_is_judged_again_and_another_fault_is_one() {
    use shekyl_chain_store::store::{AltCannot, StoreCannot, StoreError};
    use shekyl_mempool::PoolFault;
    let (mut x, prefix) = matured("svc-pool-moved-x").await;
    let tx = paying_the_floor(&mut x, &prefix, 0).await;
    let txid = tx.txid_parts().hash;
    let moved = PoolFault::TipMoved {
        asked: shekyl_types::BlockHeight::from_raw(5),
        now: shekyl_types::BlockHeight::from_raw(6),
    };
    let lookup = |id: &TxHash| (*id == txid).then(|| tx.clone());
    assert_eq!(
        super::moved_bodies(vec![(txid, moved)], lookup).expect("judged again"),
        vec![tx.clone()]
    );
    let other = PoolFault::Chain(shekyl_chain_rules::Fault::View(StoreError::Cannot(
        StoreCannot::Alt(AltCannot::NotHeld),
    )));
    assert!(super::moved_bodies(vec![(txid, other)], lookup).is_err());
    x.close().await;
}
