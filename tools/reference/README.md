# Reference Implementation: derive_output_secrets

Standalone Python implementation of Shekyl's HKDF-based output secret derivation.
Generates locked test vectors for `docs/test_vectors/PQC_OUTPUT_SECRETS.json`.

## Usage

```bash
pip install -r requirements.txt
python derive_output_secrets.py
```

Outputs `../../docs/test_vectors/PQC_OUTPUT_SECRETS.json` and prints the HKDF
label registry tables (markdown) to stdout.

Both the Rust implementation and any future port must match the JSON vectors
byte-for-byte. Any change to this script or its output is a consensus change.
