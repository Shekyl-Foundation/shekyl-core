// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record's codec and construction rules — DRS-E1 S-POOL commit 1
//! (`DRS_E1_SPOOL.md` §7): every arm round-trips, every refusal fires, no
//! byte reaches a phase but its own (SPL-14), and the C++ bit patterns mean
//! what the record says they mean.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{
    BlockHash, BlockHeight, FcmpVerificationHash, NetZone, RelayCategory, RelayMethod, UnixSeconds,
};
use shekyl_units::AtomicUnits;

use super::{
    BlockRef, Origin, PoolRecord, Readiness, RecordShapeError, RelayPhase, Responsibility,
};

fn secs(n: u64) -> UnixSeconds {
    UnixSeconds::from_raw(n)
}

fn arrived(phase: RelayPhase) -> PoolRecord {
    PoolRecord {
        weight: 900,
        fee: AtomicUnits::from_raw(12_345),
        receive_time: secs(1_000),
        origin: Origin::Arrived { zone: NetZone::I2p },
        phase,
        responsibility: None,
        relayed: false,
        double_spend_seen: false,
        readiness: Readiness::default(),
        fcmp_cache: None,
    }
}

fn originated(phase: RelayPhase, responsibility: Responsibility) -> PoolRecord {
    PoolRecord {
        origin: Origin::Originated,
        responsibility: Some(responsibility),
        ..arrived(phase)
    }
}

fn round_trip(r: PoolRecord) -> PoolRecord {
    let bytes = r.encode();
    let back = PoolRecord::decode(&bytes).expect("decodes");
    assert_eq!(back, r);
    back
}

fn reason(e: &CodecError) -> &'static str {
    match e {
        CodecError::Invalid { reason, .. } => reason,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn every_phase_and_clock_arm_round_trips() {
    round_trip(arrived(RelayPhase::Stem {
        next_attempt: secs(5),
    }));
    round_trip(arrived(RelayPhase::Fluff { last_relayed: None }));
    round_trip(arrived(RelayPhase::Fluff {
        last_relayed: Some(secs(7)),
    }));
    round_trip(arrived(RelayPhase::Block { last_relayed: None }));
    round_trip(arrived(RelayPhase::Block {
        last_relayed: Some(secs(u64::MAX)),
    }));
    round_trip(originated(
        RelayPhase::Held { last_attempt: None },
        Responsibility::Armed,
    ));
    round_trip(originated(
        RelayPhase::Held {
            last_attempt: Some(secs(1_000)),
        },
        Responsibility::Armed,
    ));
    round_trip(originated(
        RelayPhase::Block {
            last_relayed: Some(secs(9)),
        },
        Responsibility::Disarmed,
    ));
    for zone in [
        NetZone::Invalid,
        NetZone::Public,
        NetZone::I2p,
        NetZone::Tor,
    ] {
        round_trip(PoolRecord {
            origin: Origin::Arrived { zone },
            ..arrived(RelayPhase::Fluff { last_relayed: None })
        });
    }
}

#[test]
fn every_optional_part_round_trips_present_and_absent() {
    let full = PoolRecord {
        relayed: true,
        double_spend_seen: true,
        readiness: Readiness {
            max_used: Some(BlockRef {
                height: BlockHeight::from_raw(10),
                hash: BlockHash::from_bytes([1; 32]),
            }),
            last_failed: Some(BlockRef {
                height: BlockHeight::from_raw(9),
                hash: BlockHash::from_bytes([2; 32]),
            }),
        },
        fcmp_cache: Some(FcmpVerificationHash::from_bytes([3; 32])),
        ..arrived(RelayPhase::Fluff {
            last_relayed: Some(secs(2)),
        })
    };
    round_trip(full);
    round_trip(arrived(RelayPhase::Fluff { last_relayed: None }));
}

/// The construction rules, at `checked()` and again at decode: a stored
/// row cannot say what a fresh one cannot (`SPL-Q9`).
#[test]
fn cross_field_rules_are_refused_at_construction_and_at_decode() {
    let cases: [(PoolRecord, RecordShapeError); 4] = [
        (
            PoolRecord {
                origin: Origin::Arrived {
                    zone: NetZone::Public,
                },
                responsibility: None,
                ..arrived(RelayPhase::Held { last_attempt: None })
            },
            RecordShapeError::HeldButArrived,
        ),
        (
            PoolRecord {
                origin: Origin::Originated,
                responsibility: Some(Responsibility::Armed),
                ..arrived(RelayPhase::Stem {
                    next_attempt: secs(1),
                })
            },
            RecordShapeError::StemButOriginated,
        ),
        // Arrived + Armed: an arrived transaction believing it owes a
        // broadcast — the invariant the ruling asked to enforce, not
        // document.
        (
            PoolRecord {
                responsibility: Some(Responsibility::Armed),
                ..arrived(RelayPhase::Fluff { last_relayed: None })
            },
            RecordShapeError::ResponsibilityWithoutOrigin,
        ),
        (
            PoolRecord {
                origin: Origin::Originated,
                responsibility: None,
                ..arrived(RelayPhase::Held { last_attempt: None })
            },
            RecordShapeError::OriginWithoutResponsibility,
        ),
    ];
    for (record, expected) in cases {
        assert_eq!(record.validate(), Err(expected));
        assert_eq!(record.checked(), Err(expected));
        // The encoder is a pure projection; the decoder is where the rule
        // is re-applied to bytes.
        let bytes = record.encode();
        let err = PoolRecord::decode(&bytes).expect_err("refused at decode");
        assert_eq!(reason(&err), expected.to_string().as_str());
    }
}

/// SPL-14 — no relay state is reachable by fall-through. Every byte
/// outside a tag's domain is an error, and `Fluff` is reached by tag 2 and
/// nothing else.
#[test]
fn unknown_tags_are_errors_and_fluff_is_reached_only_by_its_own_byte() {
    let base = arrived(RelayPhase::Fluff { last_relayed: None });
    let bytes = base.encode();
    // Offsets: weight 0..8, fee 8..16, receive_time 16..24, origin tag 24,
    // zone 25, phase tag 26.
    let (origin_at, zone_at, phase_at) = (24, 25, 26);
    assert_eq!(bytes[origin_at], 1);
    assert_eq!(bytes[zone_at], NetZone::I2p.to_byte());
    assert_eq!(bytes[phase_at], 2);

    let mut fluff_seen = 0;
    for b in 0..=u8::MAX {
        let mut mutated = bytes.clone();
        mutated[phase_at] = b;
        match PoolRecord::decode(&mutated) {
            Ok(r) => {
                assert!(b <= 3, "phase tag {b} decoded to {:?}", r.phase);
                if matches!(r.phase, RelayPhase::Fluff { .. }) {
                    fluff_seen += 1;
                    assert_eq!(b, 2);
                }
            }
            // Tags 0 (Held) and 1 (Stem) read on, and refuse for a different
            // reason (Held on an Arrived entry; the Stem clock over-reads).
            Err(e) => assert!(b == 0 || b == 1 || b > 3, "phase tag {b}: {}", reason(&e)),
        }
    }
    assert_eq!(fluff_seen, 1);

    for b in 2..=u8::MAX {
        let mut mutated = bytes.clone();
        mutated[origin_at] = b;
        let err = PoolRecord::decode(&mutated).expect_err("origin tag refused");
        assert_eq!(reason(&err), "origin tag is not Originated or Arrived");
    }
    for b in 4..=u8::MAX {
        let mut mutated = bytes.clone();
        mutated[zone_at] = b;
        let err = PoolRecord::decode(&mutated).expect_err("zone byte refused");
        assert_eq!(reason(&err), "origin zone byte is not a NetZone");
    }
}

#[test]
fn flag_and_presence_bytes_are_exactly_zero_or_one() {
    let base = arrived(RelayPhase::Fluff { last_relayed: None });
    let bytes = base.encode();
    // After phase tag (26) and its absent clock (27): responsibility 28,
    // relayed 29, double_spend_seen 30, max_used presence 31, last_failed
    // presence 32, fcmp presence 33.
    for (at, what) in [
        (27, "Fluff presence byte is not 0 or 1"),
        (28, "responsibility tag is not none, Armed or Disarmed"),
        (29, "relayed byte is not 0 or 1"),
        (30, "double_spend_seen byte is not 0 or 1"),
        (31, "max_used presence byte is not 0 or 1"),
        (32, "last_failed presence byte is not 0 or 1"),
        (33, "fcmp_cache presence byte is not 0 or 1"),
    ] {
        let mut mutated = bytes.clone();
        mutated[at] = 0x7f;
        let err = PoolRecord::decode(&mutated).expect_err("refused");
        assert_eq!(reason(&err), what, "byte {at}");
    }
    assert_eq!(bytes.len(), 34);
}

#[test]
fn truncated_and_trailing_bytes_are_refused() {
    let full = arrived(RelayPhase::Stem {
        next_attempt: secs(1),
    })
    .encode();
    for cut in 0..full.len() {
        assert!(PoolRecord::decode(&full[..cut]).is_err(), "cut at {cut}");
    }
    let mut trailing = full.clone();
    trailing.push(0);
    let err = PoolRecord::decode(&trailing).expect_err("trailing refused");
    assert_eq!(reason(&err), "trailing bytes after the pool record");
}

/// The ratchet and the pin as one rule (`RelayPhase::upgrade`).
#[test]
fn upgrade_is_the_ratchet_and_the_pin() {
    let held = RelayPhase::Held { last_attempt: None };
    let stem = RelayPhase::Stem {
        next_attempt: secs(1),
    };
    let fluff = RelayPhase::Fluff { last_relayed: None };
    let block = RelayPhase::Block { last_relayed: None };
    let peer = Origin::Arrived {
        zone: NetZone::Public,
    };
    // An arrival walks Stem → Fluff → Block and never backwards or to Held.
    assert_eq!(stem.upgrade(peer, fluff), Some(fluff));
    assert_eq!(stem.upgrade(peer, block), Some(block));
    assert_eq!(fluff.upgrade(peer, block), Some(block));
    assert_eq!(fluff.upgrade(peer, stem), None);
    assert_eq!(
        fluff.upgrade(peer, fluff),
        None,
        "same phase is not a transition"
    );
    assert_eq!(stem.upgrade(peer, held), None, "an arrival is never Held");
    // An originated entry refuses a peer's Stem or Fluff and yields only to
    // proof of work.
    assert_eq!(held.upgrade(Origin::Originated, stem), None);
    assert_eq!(held.upgrade(Origin::Originated, fluff), None);
    assert_eq!(held.upgrade(Origin::Originated, block), Some(block));
    assert_eq!(block.upgrade(Origin::Originated, block), None);
}

/// The C++ record's meanings, transcribed as a table (`DRS_E1_SPOOL.md` §7
/// commit 1): for each `set_relay_method` pattern over the four class bits
/// — with `observed_circulating` varied independently — and each
/// `last_relayed_time` case, the `PoolRecord` the struct means, and the
/// `relay_method` byte the seam hands back. There is no byte corpus to
/// capture: the C++ encoding is `memcpy` of a C struct and nothing is meant
/// to survive it (`SPL-Q3`).
#[test]
fn the_cxx_bit_patterns_mean_what_the_record_says() {
    struct Cxx {
        kept_by_block: bool,
        is_local: bool,
        dandelionpp_stem: bool,
        observed_circulating: bool,
        /// `u64::MAX` at `add_tx` admission; `receive_time` at
        /// `insert_attested_tx`; a future deadline for stem; a past relay.
        last_relayed_time: u64,
        receive_time: u64,
    }
    // What each pattern means, as the record spells it.
    let meaning = |c: &Cxx| -> (Origin, RelayPhase, Option<Responsibility>, RelayMethod) {
        let clock = |t: u64| (t != u64::MAX).then_some(secs(t));
        if c.is_local {
            // `local`: originated, held; the clock is the last private
            // attempt (`receive_time` on the attested path, none on the
            // dispatch path); responsibility armed until observed.
            (
                Origin::Originated,
                RelayPhase::Held {
                    last_attempt: clock(c.last_relayed_time),
                },
                Some(if c.observed_circulating {
                    Responsibility::Disarmed
                } else {
                    Responsibility::Armed
                }),
                RelayMethod::Local,
            )
        } else if c.dandelionpp_stem {
            (
                Origin::Arrived {
                    zone: NetZone::Public,
                },
                RelayPhase::Stem {
                    next_attempt: secs(c.last_relayed_time),
                },
                None,
                RelayMethod::Stem,
            )
        } else if c.kept_by_block {
            (
                Origin::Arrived {
                    zone: NetZone::Invalid,
                },
                RelayPhase::Block {
                    last_relayed: clock(c.last_relayed_time),
                },
                None,
                RelayMethod::Block,
            )
        } else {
            // All four class bits clear: fluff — by its own pattern, not by
            // fall-through (SPL-14).
            (
                Origin::Arrived {
                    zone: NetZone::Public,
                },
                RelayPhase::Fluff {
                    last_relayed: clock(c.last_relayed_time),
                },
                None,
                RelayMethod::Fluff,
            )
        }
    };
    let clocks = [
        u64::MAX,
        1_000, /* receive_time */
        1_190, /* future */
        900,   /* past */
    ];
    let mut rows = 0;
    for (kept_by_block, is_local, dandelionpp_stem) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
        (false, false, false),
    ] {
        for observed_circulating in [false, true] {
            for last_relayed_time in clocks {
                let c = Cxx {
                    kept_by_block,
                    is_local,
                    dandelionpp_stem,
                    observed_circulating,
                    last_relayed_time,
                    receive_time: 1_000,
                };
                let (origin, phase, responsibility, method) = meaning(&c);
                // A stem entry's clock is a deadline: the sentinel is not a
                // legal stem clock, so that row has no meaning to check.
                if matches!(phase, RelayPhase::Stem { .. }) && last_relayed_time == u64::MAX {
                    continue;
                }
                let record = PoolRecord {
                    origin,
                    phase,
                    responsibility,
                    receive_time: secs(c.receive_time),
                    ..arrived(RelayPhase::Fluff { last_relayed: None })
                }
                .checked()
                .expect("every C++ pattern has a well-formed record");
                assert_eq!(record.relay_method(), method);
                assert_eq!(
                    record.matches(RelayCategory::Broadcasted),
                    matches!(method, RelayMethod::Fluff | RelayMethod::Block)
                );
                assert!(record.matches(RelayCategory::Relayable));
                assert!(record.matches(RelayCategory::All));
                // The independent bit shifts nothing but the responsibility.
                if !is_local {
                    assert_eq!(record.responsibility, None);
                }
                round_trip(record);
                rows += 1;
            }
        }
    }
    assert_eq!(
        rows,
        4 * 2 * 4 - 2,
        "the two sentinel-stem rows have no meaning"
    );
    // The fifth C++ pattern, `do_not_relay` (`relay_method::none`), has no
    // record: nothing writes it, and `RelayMethod::None` has no preimage.
}
