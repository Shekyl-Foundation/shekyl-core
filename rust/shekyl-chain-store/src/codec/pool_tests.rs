// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool record's codec and its walk — DRS-E1 S-POOL.
//!
//! Every arm round-trips, every illegal tag is an error, fluff is reached
//! by its own tag only (SPL-14), the null verification hash is refused
//! (SPL-10), and [`RelayState::upgrade`] is the forward walk.

use shekyl_store_codec::{Canonical, CodecError};
use shekyl_types::{
    BlockHash, BlockHeight, FcmpVerificationHash, NetZone, RelayCategory, RelayMethod, UnixSeconds,
};
use shekyl_units::AtomicUnits;

use super::{
    ArrivedPhase, BlockRef, Origin, OriginatedPhase, PoolRecord, Readiness, RelayState,
    Responsibility,
};

fn secs(n: u64) -> UnixSeconds {
    UnixSeconds::from_raw(n)
}

fn arrived(phase: ArrivedPhase) -> PoolRecord {
    PoolRecord {
        weight: 900,
        fee: AtomicUnits::from_raw(12_345),
        receive_time: secs(1_000),
        relay_state: RelayState::Arrived {
            zone: NetZone::I2p,
            phase,
        },
        relayed: false,
        double_spend_seen: false,
        readiness: Readiness::default(),
        fcmp_cache: None,
    }
}

fn originated(phase: OriginatedPhase, responsibility: Responsibility) -> PoolRecord {
    PoolRecord {
        relay_state: RelayState::Originated {
            phase,
            responsibility,
        },
        ..arrived(ArrivedPhase::Fluff { last_relayed: None })
    }
}

fn round_trip(record: PoolRecord) -> PoolRecord {
    let back = PoolRecord::decode(&record.encode()).expect("decodes");
    assert_eq!(back, record);
    back
}

fn reason(err: &CodecError) -> &'static str {
    match err {
        CodecError::Invalid { reason, .. } => reason,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

/// The relay tag sits after weight, fee and receive_time, eight bytes each.
const RELAY_TAG_AT: usize = 24;

#[test]
fn every_phase_and_clock_arm_round_trips() {
    round_trip(arrived(ArrivedPhase::Stem {
        next_attempt: secs(5),
    }));
    round_trip(arrived(ArrivedPhase::Fluff { last_relayed: None }));
    round_trip(arrived(ArrivedPhase::Fluff {
        last_relayed: Some(secs(7)),
    }));
    round_trip(arrived(ArrivedPhase::Block { last_relayed: None }));
    round_trip(arrived(ArrivedPhase::Block {
        last_relayed: Some(secs(u64::MAX)),
    }));
    round_trip(originated(
        OriginatedPhase::Held { last_attempt: None },
        Responsibility::Armed,
    ));
    round_trip(originated(
        OriginatedPhase::Held {
            last_attempt: Some(secs(1_000)),
        },
        Responsibility::Armed,
    ));
    round_trip(originated(
        OriginatedPhase::Block {
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
            relay_state: RelayState::Arrived {
                zone,
                phase: ArrivedPhase::Fluff { last_relayed: None },
            },
            ..arrived(ArrivedPhase::Fluff { last_relayed: None })
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
        ..arrived(ArrivedPhase::Fluff {
            last_relayed: Some(secs(2)),
        })
    };
    round_trip(full);
    round_trip(arrived(ArrivedPhase::Fluff { last_relayed: None }));
}

#[test]
fn a_null_verification_hash_is_not_a_cache_hit() {
    let mut bytes = PoolRecord {
        fcmp_cache: Some(FcmpVerificationHash::from_bytes([0xfc; 32])),
        ..arrived(ArrivedPhase::Fluff { last_relayed: None })
    }
    .encode();
    let hash_at = bytes.len() - 32;
    bytes[hash_at..].fill(0);
    let err = PoolRecord::decode(&bytes).expect_err("null hash refused");
    assert_eq!(
        reason(&err),
        "fcmp cache is the null hash; absence is a missing option"
    );
    assert!(!arrived(ArrivedPhase::Fluff { last_relayed: None }).has_null_fcmp_cache());
}

/// SPL-14 — fluff is its own tag. A zero tag is the held arm, which still
/// has to parse a responsibility, and it does not become fluff.
#[test]
fn unknown_tags_are_errors_and_fluff_is_reached_only_by_its_own_byte() {
    let bytes = arrived(ArrivedPhase::Fluff { last_relayed: None }).encode();
    assert_eq!(bytes[RELAY_TAG_AT], 3, "fluff's tag");

    let mut fluff_seen = 0;
    for tag in 0..=u8::MAX {
        let mut mutated = bytes.clone();
        mutated[RELAY_TAG_AT] = tag;
        match PoolRecord::decode(&mutated) {
            Ok(record) => {
                assert!(tag <= 4, "tag {tag} decoded");
                if record.relay_method() == RelayMethod::Fluff {
                    fluff_seen += 1;
                    assert_eq!(tag, 3);
                }
            }
            Err(_) => assert_ne!(tag, 3, "fluff's own tag refused"),
        }
    }
    assert_eq!(fluff_seen, 1);

    // A zero tag is the held arm. When the bytes that follow parse, the
    // result is an originated entry, not a broadcast.
    let mut zeroed = bytes.clone();
    zeroed[RELAY_TAG_AT] = 0;
    if let Ok(record) = PoolRecord::decode(&zeroed) {
        assert_eq!(record.origin(), Origin::Originated);
        assert_eq!(record.relay_method(), RelayMethod::Local);
        assert!(!record.matches(RelayCategory::Broadcasted));
    }
}

#[test]
fn flag_zone_and_responsibility_bytes_are_closed() {
    let fluff = arrived(ArrivedPhase::Fluff { last_relayed: None }).encode();
    // tag, zone, absent clock, then the two flags and three presence bytes.
    assert_eq!(fluff.len(), 32);
    for (at, what) in [
        (26, "Fluff presence byte is not 0 or 1"),
        (27, "relayed byte is not 0 or 1"),
        (28, "double_spend_seen byte is not 0 or 1"),
        (29, "max_used presence byte is not 0 or 1"),
        (30, "last_failed presence byte is not 0 or 1"),
        (31, "fcmp_cache presence byte is not 0 or 1"),
    ] {
        let mut mutated = fluff.clone();
        mutated[at] = 0x7f;
        let err = PoolRecord::decode(&mutated).expect_err("refused");
        assert_eq!(reason(&err), what, "byte {at}");
    }

    let mut zone = fluff.clone();
    zone[25] = 0xff;
    assert_eq!(
        reason(&PoolRecord::decode(&zone).unwrap_err()),
        "arrival zone byte is not a NetZone"
    );

    let held = originated(
        OriginatedPhase::Held { last_attempt: None },
        Responsibility::Armed,
    )
    .encode();
    assert_eq!(held[RELAY_TAG_AT], 0);
    assert_eq!(held[RELAY_TAG_AT + 1], 1, "Armed");
    let mut responsibility = held.clone();
    responsibility[RELAY_TAG_AT + 1] = 0;
    assert_eq!(
        reason(&PoolRecord::decode(&responsibility).unwrap_err()),
        "responsibility tag is not Armed or Disarmed"
    );
}

#[test]
fn truncated_and_trailing_bytes_are_refused() {
    let full = arrived(ArrivedPhase::Stem {
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

/// The walk: an arrival moves `Stem → Fluff → Block` (stem may skip fluff);
/// an originated entry moves `Held → Block` only. Same phase is not a step.
/// A different zone is refused here and is `OriginChanged` at the store.
#[test]
fn upgrade_is_the_forward_walk_and_accepts_keeps_the_same_phase() {
    let stem = RelayState::Arrived {
        zone: NetZone::Public,
        phase: ArrivedPhase::Stem {
            next_attempt: secs(1),
        },
    };
    let fluff = RelayState::Arrived {
        zone: NetZone::Public,
        phase: ArrivedPhase::Fluff { last_relayed: None },
    };
    let arrived_block = RelayState::Arrived {
        zone: NetZone::Public,
        phase: ArrivedPhase::Block { last_relayed: None },
    };
    let held = RelayState::Originated {
        phase: OriginatedPhase::Held { last_attempt: None },
        responsibility: Responsibility::Armed,
    };
    let originated_block = RelayState::Originated {
        phase: OriginatedPhase::Block { last_relayed: None },
        responsibility: Responsibility::Disarmed,
    };

    assert_eq!(stem.upgrade(fluff), Some(fluff));
    assert_eq!(stem.upgrade(arrived_block), Some(arrived_block));
    assert_eq!(fluff.upgrade(arrived_block), Some(arrived_block));
    assert_eq!(
        fluff.upgrade(stem),
        None,
        "an arrival does not walk backwards"
    );
    assert_eq!(fluff.upgrade(fluff), None, "same phase is not a step");
    assert!(fluff.accepts(RelayState::Arrived {
        zone: NetZone::Public,
        phase: ArrivedPhase::Fluff {
            last_relayed: Some(secs(9)),
        },
    }));

    assert_eq!(held.upgrade(originated_block), Some(originated_block));
    assert_eq!(originated_block.upgrade(held), None);
    assert_eq!(held.upgrade(stem), None);
    assert_eq!(held.upgrade(fluff), None);
    assert!(held.accepts(RelayState::Originated {
        phase: OriginatedPhase::Held {
            last_attempt: Some(secs(4)),
        },
        responsibility: Responsibility::Disarmed,
    }));

    let other_zone = RelayState::Arrived {
        zone: NetZone::Tor,
        phase: ArrivedPhase::Fluff { last_relayed: None },
    };
    assert_eq!(fluff.upgrade(other_zone), None);
    assert!(!fluff.accepts(other_zone));
    assert_eq!(
        fluff.origin(),
        Origin::Arrived {
            zone: NetZone::Public
        }
    );
    assert_eq!(held.origin(), Origin::Originated);
    assert_eq!(held.responsibility(), Some(Responsibility::Armed));
    assert_eq!(fluff.responsibility(), None);
}

/// The C++ record's meanings, transcribed as a table. There is no byte
/// corpus: the C++ encoding is `memcpy` of a struct (SPL-Q3). An originated
/// entry that has yielded to a block is not one of these rows — the C++
/// clears `is_local` to say block — and the round-trip above holds that
/// pair, which this record can say and the C++ word cannot.
#[test]
fn the_cxx_bit_patterns_mean_what_the_record_says() {
    struct Cxx {
        kept_by_block: bool,
        is_local: bool,
        dandelionpp_stem: bool,
        observed_circulating: bool,
        last_relayed_time: u64,
        receive_time: u64,
    }
    let meaning = |c: &Cxx| -> (RelayState, RelayMethod) {
        let clock = |t: u64| (t != u64::MAX).then_some(secs(t));
        if c.is_local {
            (
                RelayState::Originated {
                    phase: OriginatedPhase::Held {
                        last_attempt: clock(c.last_relayed_time),
                    },
                    responsibility: if c.observed_circulating {
                        Responsibility::Disarmed
                    } else {
                        Responsibility::Armed
                    },
                },
                RelayMethod::Local,
            )
        } else if c.dandelionpp_stem {
            (
                RelayState::Arrived {
                    zone: NetZone::Public,
                    phase: ArrivedPhase::Stem {
                        next_attempt: secs(c.last_relayed_time),
                    },
                },
                RelayMethod::Stem,
            )
        } else if c.kept_by_block {
            (
                RelayState::Arrived {
                    zone: NetZone::Invalid,
                    phase: ArrivedPhase::Block {
                        last_relayed: clock(c.last_relayed_time),
                    },
                },
                RelayMethod::Block,
            )
        } else {
            (
                RelayState::Arrived {
                    zone: NetZone::Public,
                    phase: ArrivedPhase::Fluff {
                        last_relayed: clock(c.last_relayed_time),
                    },
                },
                RelayMethod::Fluff,
            )
        }
    };
    let clocks = [u64::MAX, 1_000, 1_190, 900];
    let mut rows = 0;
    for (kept_by_block, is_local, dandelionpp_stem) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
        (false, false, false),
    ] {
        for observed_circulating in [false, true] {
            for last_relayed_time in clocks {
                let cxx = Cxx {
                    kept_by_block,
                    is_local,
                    dandelionpp_stem,
                    observed_circulating,
                    last_relayed_time,
                    receive_time: 1_000,
                };
                let (relay_state, method) = meaning(&cxx);
                if matches!(
                    relay_state,
                    RelayState::Arrived {
                        phase: ArrivedPhase::Stem { .. },
                        ..
                    }
                ) && last_relayed_time == u64::MAX
                {
                    continue;
                }
                let record = PoolRecord {
                    relay_state,
                    receive_time: secs(cxx.receive_time),
                    ..arrived(ArrivedPhase::Fluff { last_relayed: None })
                };
                assert_eq!(record.relay_method(), method);
                assert_eq!(
                    record.matches(RelayCategory::Broadcasted),
                    matches!(method, RelayMethod::Fluff | RelayMethod::Block)
                );
                assert!(record.matches(RelayCategory::Relayable));
                assert!(record.matches(RelayCategory::All));
                if !is_local {
                    assert_eq!(record.responsibility(), None);
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
    // Yielding to a block keeps provenance. The seam byte becomes Block.
    let yielded = originated(
        OriginatedPhase::Block { last_relayed: None },
        Responsibility::Disarmed,
    );
    assert_eq!(yielded.origin(), Origin::Originated);
    assert_eq!(yielded.relay_method(), RelayMethod::Block);
    assert!(yielded.matches(RelayCategory::Broadcasted));
}
