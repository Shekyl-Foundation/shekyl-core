// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The request switches that select reply fields (`RPC_WIRE.md` RW-Q4).

use super::Shape;

/// The switches a request turned on that select fields of `reply`
/// (RW-Q4): each [`Shape::Asked`] names a request switch, and it is on when
/// the request carries it as `true`. A switch the request leaves out is
/// off: every switch defaults off.
#[must_use]
pub fn switches_on(request: &serde_json::Value, reply: &Shape) -> Vec<&'static str> {
    let mut on = switches(reply);
    on.retain(|switch| request.get(*switch) == Some(&serde_json::Value::Bool(true)));
    on
}

/// The switches a method's request takes that select fields of its
/// `reply`: a field selected by a switch the request does not take is
/// never in that method's reply (`block_list`'s headers carry no `pow`).
#[must_use]
pub fn request_switches(request: &Shape, reply: &Shape) -> Vec<&'static str> {
    let taken: Vec<&'static str> = match request {
        Shape::Object { fields, choice, .. } => fields
            .iter()
            .chain(choice.iter().flatten())
            .map(|field| field.name)
            .collect(),
        _ => Vec::new(),
    };
    let mut on = switches(reply);
    on.retain(|switch| taken.contains(switch));
    on
}

/// Every switch that selects a field of `reply`, sorted, each once.
#[must_use]
pub fn switches(reply: &Shape) -> Vec<&'static str> {
    let mut switches = Vec::new();
    collect_switches(reply, &mut switches);
    switches.sort_unstable();
    switches.dedup();
    switches
}

fn collect_switches(shape: &Shape, out: &mut Vec<&'static str>) {
    match shape {
        Shape::Asked { switch, inner } => {
            out.push(switch);
            collect_switches(inner, out);
        }
        Shape::Object {
            fields,
            parts,
            choice,
            ..
        } => {
            for field in fields
                .iter()
                .chain(parts.iter().flat_map(|part| &part.fields))
                .chain(choice.iter().flatten())
            {
                collect_switches(&field.shape, out);
            }
        }
        Shape::Tagged { variants, .. } => {
            for field in variants.iter().flat_map(|(_, fields)| fields) {
                collect_switches(&field.shape, out);
            }
        }
        Shape::List(inner)
        | Shape::Nullable(inner)
        | Shape::Optional(inner)
        | Shape::Hidden { inner, .. }
        | Shape::Map { value: inner, .. } => collect_switches(inner, out),
        Shape::Either(item, slot) => {
            collect_switches(item, out);
            collect_switches(slot, out);
        }
        Shape::States(states) => {
            for payload in states.iter().filter_map(|(_, payload)| payload.as_ref()) {
                collect_switches(payload, out);
            }
        }
        Shape::Scalar(_) | Shape::OneOf(_) | Shape::Null | Shape::Empty => {}
    }
}
