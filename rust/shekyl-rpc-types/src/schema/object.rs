// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

/// A wire object: the struct, its serde derives and its [`Schema`], written
/// together.
///
/// The holder is the glossary path of what the object describes. A field
/// may carry one bracket after its name:
///
/// - `["tx"]`: the name walks under another holder (a modifier, IG-Q42);
/// - `[optional]` or `[optional "tx"]`: a request parameter that may be
///   left out. Its type is `Option<T>`, or `bool` with `#[serde(default)]`
///   for a switch that defaults off. Refused in a reply ([`kind_faults`]).
/// - `[asked "switch"]`: a reply field present exactly when the request
///   turned `switch` on (RW-Q4). Its type is [`Asked<T>`](crate::kinds::Asked),
///   and it carries `#[serde(default, skip_serializing_if =
///   "Asked::is_unasked")]`.
/// - `[shown POLICY]`: the field is shown only to a caller that policy
///   admits. Its type is [`Withheld<T>`](crate::kinds::Withheld), and it
///   carries `#[serde(default, skip_serializing_if =
///   "Withheld::is_withheld")]`; a withheld field that is not skipped
///   fails to serialize, so the attribute cannot be forgotten.
///
/// Every other field is required on the wire and unknown keys are refused;
/// a field with no answer is `Nullable`, written `null` (RK-D23). A field's
/// name is checked at compile time to be `[a-z][a-z0-9_]*`.
///
/// ```
/// shekyl_rpc_types::wire_object! {
///     /// The chain's tip.
///     ["chain"]
///     pub struct Tip {
///         /// The tip's height.
///         pub height: shekyl_rpc_types::kinds::Height,
///     }
/// }
/// ```
///
/// A raw identifier is not a wire name, and does not compile:
///
/// ```compile_fail
/// shekyl_rpc_types::wire_object! {
///     ["chain"]
///     pub struct Tip {
///         pub r#type: shekyl_rpc_types::kinds::Height,
///     }
/// }
/// ```
///
/// Nor does a field of a type with no kind, such as `u64` or `Option`:
///
/// ```compile_fail
/// shekyl_rpc_types::wire_object! {
///     ["chain"]
///     pub struct Tip {
///         pub height: u64,
///     }
/// }
/// ```
#[macro_export]
macro_rules! wire_object {
    (
        $(#[$meta:meta])*
        [$holder:literal]
        $vis:vis struct $name:ident {
            $(
                $(#[$fmeta:meta])*
                $fvis:vis $field:ident $([$($modifier:tt)+])? : $fty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        $vis struct $name {
            $(
                $(#[$fmeta])*
                $fvis $field: $fty,
            )*
        }

        const _: () = {
            $($crate::method::assert_name(::core::stringify!($field));)*
        };

        impl $crate::schema::Schema for $name {
            fn shape() -> $crate::schema::Shape {
                $crate::schema::Shape::Object {
                    holder: $holder,
                    fields: ::std::vec![
                        $($crate::schema::Field {
                            name: ::core::stringify!($field),
                            under: $crate::wire_object!(@under $($($modifier)+)?),
                            shape: $crate::wire_object!(@shape $fty; $($($modifier)+)?),
                        },)*
                    ],
                    parts: ::std::vec::Vec::new(),
                    choice: ::std::vec::Vec::new(),
                }
            }
        }
    };
    (@under) => { ::core::option::Option::None };
    (@under $under:literal) => { ::core::option::Option::Some($under) };
    (@under shown $policy:expr) => { ::core::option::Option::None };
    (@under asked $switch:literal) => { ::core::option::Option::None };
    (@under optional) => { ::core::option::Option::None };
    (@under optional $under:literal) => { ::core::option::Option::Some($under) };
    (@shape $fty:ty;) => { <$fty as $crate::schema::Schema>::shape() };
    (@shape $fty:ty; $under:literal) => { <$fty as $crate::schema::Schema>::shape() };
    (@shape $fty:ty; optional $($under:literal)?) => {
        $crate::schema::Shape::Optional(::std::boxed::Box::new(
            <$fty as $crate::kinds::OptionalShape>::inner_shape(),
        ))
    };
    (@shape $fty:ty; asked $switch:literal) => {
        $crate::schema::Shape::Asked {
            switch: $switch,
            inner: ::std::boxed::Box::new(
                <$fty as $crate::kinds::AskedShape>::inner_shape(),
            ),
        }
    };
    (@shape $fty:ty; shown $policy:expr) => {
        $crate::schema::Shape::Hidden {
            shown_to: $policy,
            inner: ::std::boxed::Box::new(
                <$fty as $crate::kinds::WithheldShape>::inner_shape(),
            ),
        }
    };
}
