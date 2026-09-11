# shekyl-portable-storage

Binary **portable_storage** codec — the self-describing KV envelope Levin
command bodies and HTTP `.bin` RPC use. Spec:
[`docs/PORTABLE_STORAGE.md`](../../docs/PORTABLE_STORAGE.md). Decision:
[`docs/design/LV2_PORTABLE_STORAGE.md`](../../docs/design/LV2_PORTABLE_STORAGE.md)
(LV-2a).

## What this crate is

- encode (`store_to_binary`) / decode (`load_from_binary`) of the 9-byte
  header, varints, sections, typed arrays, and little-endian POD values
- DoS limits as a **parameter**: Levin defaults (8192 / 16384 / 16384) and
  HTTP `.bin` defaults (65536×3)
- byte-identity KATs against C++ `epee::serialization::portable_storage`

## What this crate is not

- Levin framing (`shekyl-levin`)
- typed command maps (`KV_SERIALIZE` / handshake / notify) — those are
  LV-2b, in `shekyl-levin`
- JSON portable_storage
- untyped arrays (tag 13) — hard error until a captured C++ body emits one
