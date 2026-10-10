// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`Nullable<T>`]: a reply member that is **required and may be `null`**
//! (`RK-D23`, `docs/design/DAEMON_RPC_KV_GET_INFO.md` §4.1).
//!
//! A member of a reply is in one of three states, and each means one thing:
//!
//! | On the wire | Meaning |
//! | --- | --- |
//! | a value, including `0` | the answer |
//! | `null` | there is no answer |
//! | member absent | the reply is not this build's shape |
//!
//! `Option<T>` cannot hold that table. serde decodes a `null` member and a
//! **missing** member to the same `None`, so a member dropped by contract
//! drift would read as "no answer" — a decode that fails open. `Nullable<T>`
//! decodes `null` to `None`, a value to `Some`, and **refuses a missing
//! member**; it always writes the member.
//!
//! Use it for every reply member whose absence means something different
//! from its nullness. Do not put `#[serde(default)]` on one: that restores
//! the merge this type exists to prevent.
//!
//! It is for the JSON replies. It reads through `deserialize_any`, so it
//! needs a self-describing format.

use serde::de::value::{MapAccessDeserializer, SeqAccessDeserializer};
use serde::de::{Deserializer, IntoDeserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use std::marker::PhantomData;

/// A required reply member that may be `null`. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullable<T>(pub Option<T>);

impl<T> Nullable<T> {
    /// There is no answer: `null` on the wire.
    pub const NULL: Self = Self(None);

    /// The answer `value`.
    pub const fn value(value: T) -> Self {
        Self(Some(value))
    }

    /// The answer, or `None` when there is none.
    pub fn into_option(self) -> Option<T> {
        self.0
    }
}

impl<T> From<Option<T>> for Nullable<T> {
    fn from(value: Option<T>) -> Self {
        Self(value)
    }
}

impl<T> From<Nullable<T>> for Option<T> {
    fn from(value: Nullable<T>) -> Self {
        value.0
    }
}

impl<T: Serialize> Serialize for Nullable<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Some(value) => value.serialize(serializer),
            None => serializer.serialize_unit(),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    /// Through `deserialize_any`, **not** `deserialize_option`.
    ///
    /// That choice is the type. When a struct member is missing, serde's
    /// derive asks the member's type to decode from a stand-in deserializer
    /// that answers `deserialize_option` with "none" and everything else
    /// with the missing-field error. `Option<T>` asks for an option and so
    /// decodes a missing member; this asks for anything and so is refused.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NullableVisitor(PhantomData))
    }
}

/// `null` is `None`; any value is handed to `T` as the value it is.
struct NullableVisitor<T>(PhantomData<T>);

/// A scalar the format produced, forwarded to `T`'s own deserializer.
macro_rules! forward_scalar {
    ($($method:ident: $ty:ty,)*) => {$(
        fn $method<E: serde::de::Error>(self, v: $ty) -> Result<Self::Value, E> {
            T::deserialize(v.into_deserializer()).map(Nullable::value)
        }
    )*};
}

impl<'de, T: Deserialize<'de>> Visitor<'de> for NullableVisitor<T> {
    type Value = Nullable<T>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a value or null")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(Nullable::NULL)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(Nullable::NULL)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        T::deserialize(deserializer).map(Nullable::value)
    }

    forward_scalar! {
        visit_bool: bool,
        visit_i64: i64,
        visit_i128: i128,
        visit_u64: u64,
        visit_u128: u128,
        visit_f64: f64,
        visit_str: &str,
        visit_string: String,
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        T::deserialize(SeqAccessDeserializer::new(seq)).map(Nullable::value)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        T::deserialize(MapAccessDeserializer::new(map)).map(Nullable::value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A reply with one nullable member of each kind the wire carries.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        count: Nullable<u64>,
        name: Nullable<String>,
        list: Nullable<Vec<u32>>,
        part: Nullable<Part>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Part {
        height: u64,
    }

    fn all_null() -> serde_json::Value {
        json!({ "count": null, "name": null, "list": null, "part": null })
    }

    #[test]
    fn null_is_no_answer() {
        assert_eq!(
            serde_json::from_value::<Reply>(all_null()).expect("null decodes"),
            Reply {
                count: Nullable::NULL,
                name: Nullable::NULL,
                list: Nullable::NULL,
                part: Nullable::NULL,
            }
        );
    }

    /// The property the type exists for, per member: remove one and the
    /// reply is refused, naming it. An `Option` member would decode.
    #[test]
    fn a_missing_member_is_refused_not_read_as_null() {
        assert!(
            serde_json::from_value::<Reply>(json!({})).is_err(),
            "{{}} is not a reply"
        );
        for member in ["count", "name", "list", "part"] {
            let mut doc = all_null();
            doc.as_object_mut().expect("an object").remove(member);
            let refusal = serde_json::from_value::<Reply>(doc)
                .expect_err("a missing member is contract drift, not null");
            assert!(
                refusal.to_string().contains(member),
                "the refusal names `{member}`: {refusal}"
            );
        }
    }

    /// The control for the test above: the same document, with the member
    /// typed `Option`, decodes. So the refusal is this type's doing.
    #[test]
    fn an_option_member_would_have_decoded_the_missing_one() {
        #[derive(Deserialize)]
        struct Lenient {
            count: Option<u64>,
        }
        let lenient: Lenient = serde_json::from_value(json!({})).expect("Option fails open");
        assert_eq!(lenient.count, None);
    }

    #[test]
    fn a_value_is_the_answer_and_zero_is_a_value() {
        let reply: Reply = serde_json::from_value(json!({
            "count": 0, "name": "", "list": [], "part": { "height": 0 },
        }))
        .expect("values decode");
        assert_eq!(
            reply,
            Reply {
                count: Nullable::value(0),
                name: Nullable::value(String::new()),
                list: Nullable::value(Vec::new()),
                part: Nullable::value(Part { height: 0 }),
            }
        );

        let reply: Reply = serde_json::from_value(json!({
            "count": u64::MAX, "name": "n", "list": [1, 2], "part": { "height": 7 },
        }))
        .expect("values decode");
        assert_eq!(reply.count, Nullable::value(u64::MAX));
        assert_eq!(reply.list, Nullable::value(vec![1, 2]));
    }

    /// Nullable does not loosen `T`: a value of the wrong type is refused,
    /// and so is an unknown key inside a nullable part.
    #[test]
    fn a_value_of_the_wrong_type_is_refused() {
        for (member, wrong) in [
            ("count", json!("7")),
            ("count", json!(-1)),
            ("count", json!(1.5)),
            ("name", json!(7)),
            ("list", json!({})),
            ("part", json!({ "height": 1, "extra": 2 })),
        ] {
            let mut doc = all_null();
            doc[member] = wrong.clone();
            assert!(
                serde_json::from_value::<Reply>(doc).is_err(),
                "`{member}`: {wrong} is not its type"
            );
        }
    }

    /// The member is always written: `null`, never omitted.
    #[test]
    fn it_always_writes_the_member() {
        let null = Reply {
            count: Nullable::NULL,
            name: Nullable::NULL,
            list: Nullable::NULL,
            part: Nullable::NULL,
        };
        assert_eq!(serde_json::to_value(&null).expect("serializes"), all_null());

        let valued = Reply {
            count: Nullable::value(0),
            name: Nullable::value("n".to_owned()),
            list: Nullable::value(vec![3]),
            part: Nullable::value(Part { height: 9 }),
        };
        let wire = serde_json::to_value(&valued).expect("serializes");
        assert_eq!(
            wire,
            json!({ "count": 0, "name": "n", "list": [3], "part": { "height": 9 } })
        );
        assert_eq!(
            serde_json::from_value::<Reply>(wire).expect("round trip"),
            valued
        );
    }

    /// The same holds from text, which is how a reply arrives.
    #[test]
    fn it_reads_from_text_as_from_a_value() {
        #[derive(Debug, PartialEq, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct One {
            target_height: Nullable<u64>,
        }
        assert_eq!(
            serde_json::from_str::<One>(r#"{"target_height":null}"#).expect("null"),
            One {
                target_height: Nullable::NULL
            }
        );
        assert_eq!(
            serde_json::from_str::<One>(r#"{"target_height":1300000}"#).expect("value"),
            One {
                target_height: Nullable::value(1_300_000)
            }
        );
        assert!(serde_json::from_str::<One>("{}").is_err());
    }
}
