// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The Tor status's shape on the wire (`INPUT_GRAMMAR.md` §23, Part G).
//!
//! The types are `shekyl-tor-status`'s, the one shape the daemon sends and
//! every client renders (`TOR_STATUS_CRATE.md`); this module states their
//! [`Schema`], so the generated schema and the grammar walk read the same
//! names the crate writes. An `Unknown` arm is not a state on the wire: it
//! is what an older reader keeps of a keyword it does not know, so no shape
//! lists it.

use shekyl_tor_status::{
    Bootstrap, Carriage, Clearnet, Connector, Fix, ManagedTor, Onion, OnionCause, OnionState,
    Origination, Pace, Posture, Skew, TorCause, TorQuiet, TorSetting, TorState, Unusable,
};

use crate::kinds::{Count, Duration, Integer, Signed, Size};
use crate::schema::{Field, Schema, Shape};

fn field(name: &'static str, shape: Shape) -> Field {
    Field {
        name,
        under: None,
        shape,
    }
}

fn object(holder: &'static str, fields: Vec<Field>) -> Shape {
    Shape::Object {
        holder,
        fields,
        parts: Vec::new(),
        choice: Vec::new(),
    }
}

fn nullable(shape: Shape) -> Shape {
    Shape::Nullable(Box::new(shape))
}

macro_rules! one_of {
    ($($ty:ty),+ $(,)?) => {$(
        impl Schema for $ty {
            fn shape() -> Shape {
                Shape::OneOf(<$ty>::KEYWORDS)
            }
        }
    )+};
}

one_of!(
    TorSetting,
    Clearnet,
    Origination,
    Connector,
    TorState,
    Fix,
    OnionState,
    Pace,
    Carriage,
);

impl Schema for Posture {
    fn shape() -> Shape {
        object(
            "posture",
            vec![
                field("tor", TorSetting::shape()),
                field("clearnet", Clearnet::shape()),
            ],
        )
    }
}

impl Schema for TorQuiet {
    fn shape() -> Shape {
        Shape::States(vec![
            ("empty", None),
            (
                "failing",
                Some(object("tor quiet", vec![field("age", Duration::shape())])),
            ),
        ])
    }
}

impl Schema for Skew {
    fn shape() -> Shape {
        Shape::States(vec![
            ("measured", Some(Signed::shape())),
            ("minimum", Some(Signed::shape())),
        ])
    }
}

impl Schema for Unusable {
    fn shape() -> Shape {
        Shape::States(vec![
            (
                "exhausted",
                Some(object(
                    "disk",
                    vec![field("free", Size::shape()), field("needed", Size::shape())],
                )),
            ),
            ("unwritable", None),
        ])
    }
}

impl Schema for TorCause {
    fn shape() -> Shape {
        Shape::States(vec![
            ("outbound-blocked", None),
            ("directory-unreachable", None),
            ("clock-skew", Some(nullable(Skew::shape()))),
            ("descriptor-limit", Some(Count::shape())),
            ("exited", Some(nullable(Signed::shape()))),
            ("unanswered", None),
            ("launch-failed", None),
            ("install-defect", None),
            ("missing", None),
            ("unavailable", None),
            ("unusable", Some(nullable(Unusable::shape()))),
            ("onion-refused", None),
            ("stranded", None),
        ])
    }
}

impl Schema for OnionCause {
    fn shape() -> Shape {
        Shape::States(vec![
            ("probe-missed", None),
            ("uploads-refused", None),
            ("descriptor-missing", None),
            ("clock-behind", Some(Duration::shape())),
        ])
    }
}

impl Schema for Onion {
    fn shape() -> Shape {
        object(
            "tor onion",
            vec![
                field("state", OnionState::shape()),
                field("age", Duration::shape()),
                field("cause", nullable(OnionCause::shape())),
            ],
        )
    }
}

impl Schema for Bootstrap {
    fn shape() -> Shape {
        object(
            "tor bootstrap",
            vec![
                field("pace", Pace::shape()),
                field("unchanged", Duration::shape()),
                field("download", nullable(Size::shape())),
                field("window", Duration::shape()),
            ],
        )
    }
}

impl Schema for ManagedTor {
    fn shape() -> Shape {
        object(
            "tor",
            vec![
                field("state", TorState::shape()),
                field("cause", nullable(TorCause::shape())),
                field("age", Duration::shape()),
                field("respawn_count", Count::shape()),
                field("progress", nullable(Integer::shape())),
                field("flagged", bool::shape()),
                field("fix", Shape::List(Box::new(Fix::shape()))),
                field("onion", nullable(Onion::shape())),
                field("bootstrap", nullable(Bootstrap::shape())),
                field("carriage", Carriage::shape()),
            ],
        )
    }
}
