// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

use super::*;

const RATE: Kind = Kind::Quantity {
    dimension: Dimension::Rate,
    min: 1,
    keywords: &["unlimited"],
};
const BYTES: Kind = Kind::Quantity {
    dimension: Dimension::Bytes,
    min: 1,
    keywords: &[],
};
const THREADS: Kind = Kind::Integer {
    min: 1,
    keywords: &["auto"],
};
const ENDPOINT: Kind = Kind::Endpoint(EndpointRule::Any);
const LOOPBACK: Kind = Kind::Endpoint(EndpointRule::Loopback);
const ENDPOINTS: Kind = Kind::List(&ENDPOINT);

fn code(r: Result<Value, Fault>) -> Code {
    r.expect_err("expected a refusal").code
}

#[test]
fn quantities_take_iec_units_and_refuse_the_ambiguous_ones() {
    assert_eq!(BYTES.parse_text("1GiB"), Ok(Value::Bytes(1 << 30)));
    assert_eq!(RATE.parse_text("2MiB/s"), Ok(Value::Rate(2 << 20)));
    assert_eq!(RATE.parse_text("unlimited"), Ok(Value::Word("unlimited")));
    assert_eq!(code(BYTES.parse_text("1GB")), Code::ValueUnit);
    assert_eq!(code(BYTES.parse_text("1 GiB")), Code::ValueUnit);
    assert_eq!(code(RATE.parse_text("0B/s")), Code::ValueRange);
    assert_eq!(code(BYTES.parse_text("-1GiB")), Code::ValueSyntax);
    assert_eq!(
        code(BYTES.parse_text("99999999999999TiB")),
        Code::ValueRange
    );
}

#[test]
fn a_rendered_quantity_parses_back_to_the_same_value() {
    for text in ["1GiB", "648000000B", "3MiB", "1KiB"] {
        let v = BYTES.parse_text(text).expect(text);
        assert_eq!(BYTES.parse_text(&v.render()), Ok(v.clone()), "{text}");
    }
    let v = RATE.parse_text("5MiB/s").unwrap();
    assert_eq!(v.render(), "5MiB/s");
}

#[test]
fn an_integer_is_plain_decimal_at_least_its_minimum_or_a_keyword() {
    assert_eq!(THREADS.parse_text("4"), Ok(Value::Integer(4)));
    assert_eq!(THREADS.parse_text("auto"), Ok(Value::Word("auto")));
    assert_eq!(code(THREADS.parse_text("0")), Code::ValueRange);
    assert_eq!(code(THREADS.parse_text("+4")), Code::ValueSyntax);
    assert_eq!(code(THREADS.parse_text("1_000")), Code::ValueSyntax);
    assert_eq!(
        code(THREADS.parse_file(&toml::Value::Integer(-2))),
        Code::ValueRange
    );
}

#[test]
fn endpoints_are_literal_addresses_with_a_nonzero_port() {
    assert!(ENDPOINT.parse_text("127.0.0.1:11029").is_ok());
    assert!(ENDPOINT.parse_text("[::1]:11029").is_ok());
    assert_eq!(
        code(ENDPOINT.parse_text("localhost:11029")),
        Code::ValueSyntax
    );
    assert_eq!(code(ENDPOINT.parse_text("127.0.0.1:0")), Code::ValueRange);
    assert_eq!(code(LOOPBACK.parse_text("0.0.0.0:11029")), Code::ValueRange);
    assert!(LOOPBACK.parse_text("[::1]:1").is_ok());
}

#[test]
fn global_unicast_excludes_every_reserved_range() {
    for not in [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "198.18.0.1",
        "203.0.113.5",
        "0.0.0.0",
        "255.255.255.255",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
    ] {
        assert!(!is_global_unicast(not.parse().unwrap()), "{not}");
    }
    for yes in ["8.8.8.8", "45.77.66.189", "2a01:4f8::1"] {
        assert!(is_global_unicast(yes.parse().unwrap()), "{yes}");
    }
}

#[test]
fn a_list_is_repeated_on_the_cli_and_none_is_the_empty_list() {
    let two = ENDPOINTS
        .parse_cli(&["127.0.0.1:1".into(), "[::1]:2".into()])
        .unwrap();
    assert!(matches!(two, Value::List(ref v) if v.len() == 2));
    assert_eq!(
        ENDPOINTS.parse_cli(&["none".into()]),
        Ok(Value::List(Vec::new()))
    );
    assert_eq!(
        code(ENDPOINTS.parse_cli(&["none".into(), "127.0.0.1:1".into()])),
        Code::ValueRange
    );
    assert_eq!(
        ENDPOINTS.parse_file(&toml::Value::String("none".into())),
        Ok(Value::List(Vec::new()))
    );
    assert_eq!(
        code(ENDPOINTS.parse_file(&toml::Value::Array(Vec::new()))),
        Code::ValueSyntax
    );
}

#[test]
fn a_scalar_given_twice_on_the_cli_is_refused() {
    assert_eq!(
        code(THREADS.parse_cli(&["2".into(), "3".into()])),
        Code::CliRepeated
    );
}

#[test]
fn origins_are_explicit_and_never_a_wildcard() {
    assert_eq!(
        Kind::Origin.parse_text("https://Example.org:8443"),
        Ok(Value::Origin("https://example.org:8443".into()))
    );
    assert!(Kind::Origin.parse_text("http://[::1]:8080").is_ok());
    assert_eq!(code(Kind::Origin.parse_text("*")), Code::ValueRange);
    for bad in [
        "https://example.org/",
        "ftp://x",
        "https://",
        "https://a b",
        "example.org",
    ] {
        assert_eq!(
            code(Kind::Origin.parse_text(bad)),
            Code::ValueSyntax,
            "{bad}"
        );
    }
}

#[test]
fn a_peer_endpoint_takes_an_onion_only_with_a_valid_checksum() {
    let host = shekyl_onion_v3::v3_onion_hostname(&curve25519_basepoint());
    let good = format!("{host}:18083");
    assert!(matches!(
        Kind::PeerEndpoint(PeerRule::OnionOnly).parse_text(&good),
        Ok(Value::Peer(PeerEndpoint::Onion { .. }))
    ));
    let mut broken = host.clone();
    broken.replace_range(0..1, if broken.starts_with('a') { "b" } else { "a" });
    assert_eq!(
        code(Kind::PeerEndpoint(PeerRule::Any).parse_text(&format!("{broken}:18083"))),
        Code::ValueSyntax
    );
    assert_eq!(
        code(Kind::PeerEndpoint(PeerRule::OnionOnly).parse_text("8.8.8.8:1")),
        Code::ValueSyntax
    );
}

/// The compressed Ed25519 base point: a valid, non-small-order key.
fn curve25519_basepoint() -> [u8; 32] {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    b
}

#[test]
fn commands_are_file_only_arrays_with_named_placeholders() {
    const NOTIFY: Kind = Kind::Command {
        placeholders: &["height", "hash"],
    };
    let ok = toml::Value::Array(vec![
        toml::Value::String("/usr/bin/logger".into()),
        toml::Value::String("block {height} {hash} 100%".into()),
    ]);
    assert!(matches!(NOTIFY.parse_file(&ok), Ok(Value::Command(ref a)) if a.len() == 2));
    let unknown = toml::Value::Array(vec![
        toml::Value::String("/bin/x".into()),
        toml::Value::String("{height} {txid}".into()),
    ]);
    assert_eq!(code(NOTIFY.parse_file(&unknown)), Code::ValuePlaceholder);
    let unmatched = toml::Value::Array(vec![
        toml::Value::String("/bin/x".into()),
        toml::Value::String("{height".into()),
    ]);
    assert_eq!(code(NOTIFY.parse_file(&unmatched)), Code::ValueSyntax);
    let relative = toml::Value::Array(vec![toml::Value::String("logger".into())]);
    assert_eq!(code(NOTIFY.parse_file(&relative)), Code::ValueSyntax);
    assert_eq!(
        code(NOTIFY.parse_cli(&["/bin/x".into()])),
        Code::ValueSurface
    );
    assert_eq!(
        code(NOTIFY.parse_file(&toml::Value::String("/bin/x {height}".into()))),
        Code::ValueSyntax
    );
}

#[test]
fn a_path_is_absolute_only() {
    assert!(matches!(
        Kind::Path.parse_text("/etc/shekyl"),
        Ok(Value::Path(_))
    ));
    assert_eq!(code(Kind::Path.parse_text("etc/shekyl")), Code::ValueSyntax);
    assert_eq!(code(Kind::Path.parse_text("./x")), Code::ValueSyntax);
}

#[test]
fn a_secret_never_shows_its_text() {
    let v = Kind::Secret
        .parse_file(&toml::Value::String("hunter2".into()))
        .unwrap();
    assert_eq!(v.render(), "set");
    assert!(!format!("{v:?}").contains("hunter2"));
    assert_eq!(
        code(Kind::Secret.parse_cli(&["hunter2".into()])),
        Code::ValueSurface
    );
}

#[test]
fn a_map_takes_key_value_pairs_from_its_closed_key_set() {
    const LEVEL: Kind = Kind::OneOf(&["error", "warn", "info"]);
    const CATEGORIES: Kind = Kind::Map {
        keys: KeyRule {
            describe: "a logging category",
            check: |k| k == "net" || k == "rpc",
        },
        value: &LEVEL,
    };
    let v = CATEGORIES
        .parse_cli(&["net=info".into(), "rpc=error".into()])
        .unwrap();
    assert_eq!(v.render(), "net=info rpc=error");
    assert_eq!(
        CATEGORIES.parse_cli(&["none".into()]),
        Ok(Value::Map(BTreeMap::new()))
    );
    assert_eq!(
        code(CATEGORIES.parse_cli(&["wallet=info".into()])),
        Code::ValueWord
    );
    assert_eq!(
        code(CATEGORIES.parse_cli(&["net".into()])),
        Code::ValueSyntax
    );
    assert_eq!(
        code(CATEGORIES.parse_cli(&["net=loud".into()])),
        Code::ValueWord
    );
}
