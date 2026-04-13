use shekyl_crypto_pq::signature::{HybridEd25519MlDsa, SignatureScheme};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn main() {
    let scheme = HybridEd25519MlDsa;
    let message = b"shekyl-pqc-v3-test-vector-001";

    let (pk, sk) = scheme.keypair_generate().expect("keygen failed");
    let sig = scheme.sign(&sk, message).expect("sign failed");

    let pk_bytes = pk.to_canonical_bytes().expect("pk canonical failed");
    let sk_bytes = sk.to_canonical_bytes().expect("sk canonical failed");
    let sig_bytes = sig.to_canonical_bytes().expect("sig canonical failed");

    let verified = scheme.verify(&pk, message, &sig).expect("verify errored");

    println!("{{");
    println!("  \"scheme\": \"ed25519_ml_dsa_65\",");
    println!(
        "  \"message_utf8\": \"{}\",",
        String::from_utf8_lossy(message)
    );
    println!("  \"message_hex\": \"{}\",", hex(message));
    println!("  \"hybrid_public_key_hex\": \"{}\",", hex(&pk_bytes));
    println!("  \"hybrid_secret_key_hex\": \"{}\",", hex(&sk_bytes));
    println!("  \"hybrid_signature_hex\": \"{}\",", hex(&sig_bytes));
    println!("  \"hybrid_public_key_len\": {},", pk_bytes.len());
    println!("  \"hybrid_secret_key_len\": {},", sk_bytes.len());
    println!("  \"hybrid_signature_len\": {},", sig_bytes.len());
    println!("  \"verify_result\": {verified}");
    println!("}}");
}
