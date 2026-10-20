// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `ClassedRecord`: the RPC channel's record framer (`RPC_CHANNEL.md`
//! section 4.4, RT-O20).
//!
//! Every record is padded to one of a table of size classes, and travels as
//! one byte naming its class, masked, then one AEAD ciphertext:
//!
//! ```text
//! masked ClassId (1) | ChaCha20-Poly1305( occupancy (2, LE) | payload | zero pad ) (class length + 16)
//! ```
//!
//! - **The class byte** is a [`ClassId`], an index into the [`ClassTable`],
//!   sent for every table, a one-row table included.
//! - **The mask** is the first byte of ChaCha20's keystream under the
//!   direction's header-protection key and this record's nonce, the nonce
//!   the record's AEAD uses. The header key is `HKDF(record key, label)`'s
//!   first output, derived again only when the direction's key epoch moves.
//! - **The associated data** is the one unmasked class byte, so a changed
//!   byte fails the tag.
//! - **The plaintext** is the 2-byte occupancy, little-endian like the nonce
//!   counter, then the payload, then zeros to the class's length. Occupancy
//!   0 is a valid record. A receiver refuses a record whose occupancy
//!   overruns its class or whose pad is not zero, so one payload has one
//!   encoding.
//!
//! On the receiving side, a short read is truncation: nothing is spent and
//! the half stays usable. A class outside the table, a failed tag and a
//! malformed plaintext are one error, [`ClassedError::Refused`], and each
//! poisons the half.
//!
//! What the mask removes is a cleartext class byte a middlebox could match.
//! It does not hide record sizes: a public set of lengths can still be cut
//! into records without keys.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use zeroize::Zeroizing;

use crate::aead::{nonce, HASH_LEN, TAG_LEN};
use crate::direction::{Direction, DirectionError, KeyEpoch};

/// The label the header-protection key is derived under. Registered in
/// `CRYPTO_DOMAIN_REGISTRY.tsv`, mechanism 7. Read only by
/// [`Direction::header_protection_key`].
pub(crate) const RECORD_HEADER_DST: &[u8] = b"shekyl/noise-record-header-v1";

/// The masked class byte in front of every record.
pub const HEADER_LEN: usize = 1;

/// The occupancy at the front of every plaintext: how many payload bytes
/// follow, the rest being pad.
pub const OCCUPANCY_LEN: usize = 2;

/// The largest plaintext one record carries, occupancy included.
pub const MAX_RECORD_PLAINTEXT: usize = u16::MAX as usize;

/// The most rows a [`ClassTable`] holds: a [`ClassId`] is one byte.
pub const CLASS_TABLE_MAX: usize = 256;

/// An index into a [`ClassTable`]. Not a length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassId(pub u8);

/// The plaintext lengths a direction's records are padded to, smallest
/// first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassTable {
    lengths: Vec<usize>,
}

/// Why a [`ClassTable`] was refused.
#[derive(Debug, Eq, PartialEq)]
pub enum ClassTableError {
    /// No rows, or more than [`CLASS_TABLE_MAX`].
    RowCount(usize),
    /// A row below [`OCCUPANCY_LEN`] or above [`MAX_RECORD_PLAINTEXT`].
    RowLength(usize),
    /// The rows are not strictly increasing. Each length has one class.
    Order,
}

impl ClassTable {
    /// A table of plaintext lengths, occupancy included, strictly
    /// increasing.
    ///
    /// # Errors
    ///
    /// [`ClassTableError`] when the table breaks one of the rules above.
    pub fn new(lengths: &[usize]) -> Result<Self, ClassTableError> {
        if lengths.is_empty() || lengths.len() > CLASS_TABLE_MAX {
            return Err(ClassTableError::RowCount(lengths.len()));
        }
        if let Some(&bad) = lengths
            .iter()
            .find(|&&l| !(OCCUPANCY_LEN..=MAX_RECORD_PLAINTEXT).contains(&l))
        {
            return Err(ClassTableError::RowLength(bad));
        }
        if lengths.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ClassTableError::Order);
        }
        Ok(Self {
            lengths: lengths.to_vec(),
        })
    }

    /// How many classes the table has. At least one.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lengths.len()
    }

    /// Never true: a table has at least one row.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lengths.is_empty()
    }

    /// A class's plaintext length, occupancy included.
    #[must_use]
    pub fn plaintext_len(&self, class: ClassId) -> Option<usize> {
        self.lengths.get(usize::from(class.0)).copied()
    }

    /// The most payload a record of `class` carries.
    #[must_use]
    pub fn max_payload(&self, class: ClassId) -> Option<usize> {
        self.plaintext_len(class).map(|l| l - OCCUPANCY_LEN)
    }

    /// A record of `class` on the wire: the class byte, the ciphertext and
    /// the tag.
    #[must_use]
    pub fn wire_len(&self, class: ClassId) -> Option<usize> {
        self.plaintext_len(class).map(|l| HEADER_LEN + l + TAG_LEN)
    }

    /// The smallest class whose record carries `payload_len` bytes.
    #[must_use]
    pub fn smallest_for(&self, payload_len: usize) -> Option<ClassId> {
        let needed = payload_len.checked_add(OCCUPANCY_LEN)?;
        let index = self.lengths.iter().position(|&l| l >= needed)?;
        u8::try_from(index).ok().map(ClassId)
    }

    /// The largest class.
    #[must_use]
    pub fn largest(&self) -> ClassId {
        // At most CLASS_TABLE_MAX rows, so the last index fits a byte.
        ClassId(u8::try_from(self.lengths.len() - 1).expect("at most 256 rows"))
    }
}

/// What [`ClassedRecord`] and the first-record functions can fail at.
#[derive(Debug, Eq, PartialEq)]
pub enum ClassedError {
    /// Not a whole record yet. Nothing was spent; read more and try again.
    Truncated,
    /// A class outside the table, a failed tag, or a plaintext that is not
    /// one payload's encoding. The receiving half is poisoned.
    Refused,
    /// A previous record was refused; this half opens nothing more.
    Poisoned,
    /// Sealing named a class the table does not have.
    UnknownClass,
    /// Sealing gave more payload than the class carries.
    PayloadTooLarge,
    /// The direction's nonce or key epoch cannot advance.
    State,
}

/// One opened record.
#[derive(Debug, Eq, PartialEq)]
pub struct Opened {
    /// The payload, without the occupancy or the pad.
    pub payload: Vec<u8>,
    /// The class it was padded to.
    pub class: ClassId,
    /// How many wire bytes it took; the next record starts after them.
    pub consumed: usize,
}

/// The header-protection key, kept against the epoch of the record key it
/// was derived from.
struct HeaderKey {
    epoch: Option<KeyEpoch>,
    key: Zeroizing<[u8; HASH_LEN]>,
}

impl HeaderKey {
    fn new() -> Self {
        Self {
            epoch: None,
            key: Zeroizing::new([0u8; HASH_LEN]),
        }
    }

    /// The mask for `direction`'s next record. Derives the key again only
    /// when the epoch has moved.
    fn mask(&mut self, direction: &Direction) -> u8 {
        let (n, epoch) = direction.next();
        if self.epoch != Some(epoch) {
            self.key = direction.header_protection_key();
            self.epoch = Some(epoch);
        }
        mask(&self.key, n)
    }
}

/// The first byte of ChaCha20's keystream under `key` and the record nonce
/// `n`, block counter 0.
fn mask(key: &[u8; HASH_LEN], n: u64) -> u8 {
    let mut cipher = ChaCha20::new(key.into(), &nonce(n));
    let mut byte = [0u8; 1];
    cipher.apply_keystream(&mut byte);
    byte[0]
}

impl From<DirectionError> for ClassedError {
    fn from(error: DirectionError) -> Self {
        match error {
            DirectionError::Decrypt => Self::Refused,
            DirectionError::State => Self::State,
        }
    }
}

/// The class and the whole record length that `header` announces as the
/// next record. Spends nothing.
fn announced(
    direction: &Direction,
    table: &ClassTable,
    header_key: &mut HeaderKey,
    header: u8,
) -> Result<(ClassId, usize), ClassedError> {
    let class = ClassId(header ^ header_key.mask(direction));
    let len = table.wire_len(class).ok_or(ClassedError::Refused)?;
    Ok((class, len))
}

/// Open the next record in `wire`. On `Refused` the caller poisons its half.
fn open_next(
    direction: &mut Direction,
    table: &ClassTable,
    header_key: &mut HeaderKey,
    wire: &[u8],
) -> Result<Opened, ClassedError> {
    let header = *wire.first().ok_or(ClassedError::Truncated)?;
    let (class, len) = announced(direction, table, header_key, header)?;
    let record = wire.get(..len).ok_or(ClassedError::Truncated)?;
    let (plaintext, _) = direction
        .open(&record[HEADER_LEN..], &[class.0])
        .map_err(ClassedError::from)?;
    let plaintext = Zeroizing::new(plaintext);
    let occupancy = usize::from(u16::from_le_bytes([plaintext[0], plaintext[1]]));
    let body = &plaintext[OCCUPANCY_LEN..];
    let (payload, pad) = body
        .split_at_checked(occupancy)
        .ok_or(ClassedError::Refused)?;
    if pad.iter().any(|&b| b != 0) {
        return Err(ClassedError::Refused);
    }
    Ok(Opened {
        payload: payload.to_vec(),
        class,
        consumed: len,
    })
}

/// The record framer over one [`Direction`]. Make one for each direction of
/// a session, with that direction's table.
pub struct ClassedRecord {
    direction: Direction,
    table: ClassTable,
    header_key: HeaderKey,
    poisoned: bool,
}

impl ClassedRecord {
    /// The framer for `direction`, padding to `table`.
    #[must_use]
    pub fn new(direction: Direction, table: ClassTable) -> Self {
        Self {
            direction,
            table,
            header_key: HeaderKey::new(),
            poisoned: false,
        }
    }

    /// The table this half pads to.
    #[must_use]
    pub fn table(&self) -> &ClassTable {
        &self.table
    }

    /// Seal `payload` as one record of `class`.
    ///
    /// # Errors
    ///
    /// [`ClassedError::UnknownClass`] or [`ClassedError::PayloadTooLarge`]
    /// before anything is spent; [`ClassedError::State`] when the direction
    /// cannot advance.
    pub fn seal(&mut self, class: ClassId, payload: &[u8]) -> Result<Vec<u8>, ClassedError> {
        let length = self
            .table
            .plaintext_len(class)
            .ok_or(ClassedError::UnknownClass)?;
        let occupancy = u16::try_from(payload.len()).map_err(|_| ClassedError::PayloadTooLarge)?;
        if payload.len() > length - OCCUPANCY_LEN {
            return Err(ClassedError::PayloadTooLarge);
        }
        let mut plaintext = Zeroizing::new(vec![0u8; length]);
        plaintext[..OCCUPANCY_LEN].copy_from_slice(&occupancy.to_le_bytes());
        plaintext[OCCUPANCY_LEN..OCCUPANCY_LEN + payload.len()].copy_from_slice(payload);
        let header = class.0 ^ self.header_key.mask(&self.direction);
        let (ciphertext, _) = self
            .direction
            .seal(&plaintext, &[class.0])
            .map_err(ClassedError::from)?;
        let mut wire = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        wire.push(header);
        wire.extend_from_slice(&ciphertext);
        Ok(wire)
    }

    /// How many wire bytes the record that starts with `header` takes.
    /// Spends nothing. A reader reads one byte, asks, then reads the rest.
    ///
    /// # Errors
    ///
    /// [`ClassedError::Refused`] for a class outside the table, which
    /// poisons this half; [`ClassedError::Poisoned`] after any refusal.
    pub fn record_len(&mut self, header: u8) -> Result<usize, ClassedError> {
        if self.poisoned {
            return Err(ClassedError::Poisoned);
        }
        let result = announced(&self.direction, &self.table, &mut self.header_key, header);
        self.poison_on_refusal(result.map(|(_, len)| len))
    }

    /// Open the record at the front of `wire`.
    ///
    /// # Errors
    ///
    /// [`ClassedError::Truncated`] when `wire` holds less than the record,
    /// with nothing spent; [`ClassedError::Refused`], which poisons this
    /// half; [`ClassedError::Poisoned`] after any refusal.
    pub fn open(&mut self, wire: &[u8]) -> Result<Opened, ClassedError> {
        if self.poisoned {
            return Err(ClassedError::Poisoned);
        }
        let result = open_next(&mut self.direction, &self.table, &mut self.header_key, wire);
        self.poison_on_refusal(result)
    }

    fn poison_on_refusal<T>(&mut self, result: Result<T, ClassedError>) -> Result<T, ClassedError> {
        if matches!(result, Err(ClassedError::Refused)) {
            self.poisoned = true;
        }
        result
    }
}

/// How many wire bytes the first record, starting with `header`, takes, for
/// a handshake that lends its receiving direction out before the session is
/// released. Spends nothing.
///
/// # Errors
///
/// [`ClassedError::Refused`] for a class outside the table.
pub fn first_record_len(
    direction: &Direction,
    table: &ClassTable,
    header: u8,
) -> Result<usize, ClassedError> {
    announced(direction, table, &mut HeaderKey::new(), header).map(|(_, len)| len)
}

/// Open the first record through a lent direction: the opener a pending
/// session is released by. The same bytes and checks as
/// [`ClassedRecord::open`].
///
/// # Errors
///
/// As [`ClassedRecord::open`]. A caller that gets anything but `Ok` drops
/// the session.
pub fn open_first_record(
    direction: &mut Direction,
    table: &ClassTable,
    wire: &[u8],
) -> Result<Opened, ClassedError> {
    open_next(direction, table, &mut HeaderKey::new(), wire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direction::REKEY_NONCES;

    fn keyed() -> Direction {
        Direction::new(
            Zeroizing::new([0x11; HASH_LEN]),
            Zeroizing::new([0x22; HASH_LEN]),
            [0x33; HASH_LEN],
        )
    }

    /// RPC_CHANNEL.md section 4.4's response classes.
    fn table() -> ClassTable {
        ClassTable::new(&[512, 16_384, 65_535]).unwrap()
    }

    fn pair() -> (ClassedRecord, ClassedRecord) {
        (
            ClassedRecord::new(keyed(), table()),
            ClassedRecord::new(keyed(), table()),
        )
    }

    /// Known answer, computed independently in Python (`hmac` over
    /// `hashlib.blake2s`, and a ChaCha20 block function checked against
    /// RFC 8439 section 2.3.2): the header key of the record key 0x22..22,
    /// and the mask at nonces 0, 7 and 999.
    #[test]
    fn known_answer_from_an_independent_implementation() {
        let direction = keyed();
        let key = direction.header_protection_key();
        assert_eq!(
            hex(&key[..]),
            "0a5950b1e43f16769fa704b21ee5165652c90d1b417d7c18eb9ce3ccc7e93897"
        );
        assert_eq!(mask(&key, 0), 193);
        assert_eq!(mask(&key, 7), 213);
        assert_eq!(mask(&key, 999), 17);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Every class round-trips at no payload, some and the most, and the
    /// wire length is the class's.
    #[test]
    fn each_class_round_trips_at_its_length() {
        let (mut send, mut recv) = pair();
        let t = table();
        for index in 0..3u8 {
            let class = ClassId(index);
            let most = t.max_payload(class).unwrap();
            for len in [0, 1, most] {
                let payload: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
                let wire = send.seal(class, &payload).unwrap();
                assert_eq!(wire.len(), t.wire_len(class).unwrap());
                let opened = recv.open(&wire).unwrap();
                assert_eq!(opened.payload, payload);
                assert_eq!(opened.class, class);
                assert_eq!(opened.consumed, wire.len());
            }
        }
    }

    #[test]
    fn the_smallest_fitting_class_is_chosen() {
        let t = table();
        assert_eq!(t.smallest_for(0), Some(ClassId(0)));
        assert_eq!(t.smallest_for(510), Some(ClassId(0)));
        assert_eq!(t.smallest_for(511), Some(ClassId(1)));
        assert_eq!(t.smallest_for(65_533), Some(ClassId(2)));
        assert_eq!(t.smallest_for(65_534), None);
        assert_eq!(t.largest(), ClassId(2));
    }

    #[test]
    fn a_payload_over_its_class_is_refused_before_anything_is_spent() {
        let (mut send, mut recv) = pair();
        assert_eq!(
            send.seal(ClassId(0), &[0u8; 511]),
            Err(ClassedError::PayloadTooLarge)
        );
        assert_eq!(send.seal(ClassId(3), b""), Err(ClassedError::UnknownClass));
        let wire = send.seal(ClassId(0), b"next").unwrap();
        assert_eq!(recv.open(&wire).unwrap().payload, b"next");
    }

    /// A short read spends nothing: the same record opens once whole.
    #[test]
    fn a_short_read_is_truncation_and_the_half_stays_usable() {
        let (mut send, mut recv) = pair();
        let wire = send.seal(ClassId(1), b"body").unwrap();
        assert_eq!(recv.open(&[]), Err(ClassedError::Truncated));
        assert_eq!(recv.open(&wire[..1]), Err(ClassedError::Truncated));
        assert_eq!(
            recv.open(&wire[..wire.len() - 1]),
            Err(ClassedError::Truncated)
        );
        assert_eq!(recv.record_len(wire[0]), Ok(wire.len()));
        assert_eq!(recv.open(&wire).unwrap().payload, b"body");
    }

    /// The class byte is bound: a byte that names another class in the
    /// table fails the tag, and the half opens nothing after.
    #[test]
    fn a_changed_class_byte_fails_and_poisons() {
        let (mut send, mut recv) = pair();
        let mut wire = send.seal(ClassId(0), b"body").unwrap();
        let good = send.seal(ClassId(0), b"after").unwrap();
        // Masked byte XOR 1 unmasks to class 1, which is in the table.
        wire[0] ^= 1;
        let len = table().wire_len(ClassId(1)).unwrap();
        wire.resize(len, 0);
        assert_eq!(recv.open(&wire), Err(ClassedError::Refused));
        assert_eq!(recv.open(&good), Err(ClassedError::Poisoned));
    }

    #[test]
    fn a_class_outside_the_table_is_refused_and_poisons() {
        let mut send = ClassedRecord::new(keyed(), table());
        let mut recv = ClassedRecord::new(keyed(), ClassTable::new(&[512]).unwrap());
        let wire = send.seal(ClassId(2), b"body").unwrap();
        assert_eq!(recv.record_len(wire[0]), Err(ClassedError::Refused));
        assert_eq!(recv.open(&wire), Err(ClassedError::Poisoned));
    }

    #[test]
    fn a_failed_tag_is_refused_and_poisons() {
        let (mut send, mut recv) = pair();
        let mut wire = send.seal(ClassId(0), b"body").unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 1;
        assert_eq!(recv.open(&wire), Err(ClassedError::Refused));
        let wire = send.seal(ClassId(0), b"next").unwrap();
        assert_eq!(recv.open(&wire), Err(ClassedError::Poisoned));
    }

    /// Seal a raw plaintext as a record, past the framer's own encoding, so
    /// the receiver's checks on occupancy and pad can be reached.
    fn raw(direction: &mut Direction, class: ClassId, plaintext: &[u8]) -> Vec<u8> {
        let header = class.0 ^ HeaderKey::new().mask(direction);
        let (ct, _) = direction.seal(plaintext, &[class.0]).unwrap();
        let mut wire = vec![header];
        wire.extend_from_slice(&ct);
        wire
    }

    /// The unmasked class byte is the associated data, exactly: a record
    /// sealed by hand under class 0's byte opens, and one whose header names
    /// class 0 but whose ciphertext was sealed under class 1's byte does
    /// not, though its length is class 0's.
    #[test]
    fn the_class_byte_is_the_associated_data() {
        for (ad, opens) in [(0u8, true), (1u8, false)] {
            let mut send = keyed();
            let mut recv = ClassedRecord::new(keyed(), table());
            let header = HeaderKey::new().mask(&send);
            let (ct, _) = send.seal(&[0u8; 512], &[ad]).unwrap();
            let mut wire = vec![header];
            wire.extend_from_slice(&ct);
            assert_eq!(recv.open(&wire).is_ok(), opens, "sealed under {ad}");
        }
    }

    #[test]
    fn an_occupancy_past_the_class_is_refused() {
        let mut send = keyed();
        let mut recv = ClassedRecord::new(keyed(), table());
        let mut plaintext = vec![0u8; 512];
        plaintext[..2].copy_from_slice(&511u16.to_le_bytes());
        let wire = raw(&mut send, ClassId(0), &plaintext);
        assert_eq!(recv.open(&wire), Err(ClassedError::Refused));
    }

    #[test]
    fn a_pad_that_is_not_zero_is_refused() {
        let mut send = keyed();
        let mut recv = ClassedRecord::new(keyed(), table());
        let mut plaintext = vec![0u8; 512];
        plaintext[..2].copy_from_slice(&4u16.to_le_bytes());
        plaintext[2..6].copy_from_slice(b"body");
        plaintext[511] = 1;
        let wire = raw(&mut send, ClassId(0), &plaintext);
        assert_eq!(recv.open(&wire), Err(ClassedError::Refused));
    }

    /// Across the rekey boundary: the last record of an epoch is masked
    /// under the old header key and the first of the next under the new one,
    /// and both open.
    #[test]
    fn the_header_key_follows_the_rekey() {
        let (mut send, mut recv) = pair();
        send.direction.force_nonce(REKEY_NONCES - 1);
        recv.direction.force_nonce(REKEY_NONCES - 1);
        let old_key = send.direction.header_protection_key();
        let last = send.seal(ClassId(0), b"last").unwrap();
        assert_eq!(last[0], mask(&old_key, REKEY_NONCES - 1));
        let new_key = send.direction.header_protection_key();
        assert_ne!(*old_key, *new_key, "rekey moved the record key");
        let first = send.seal(ClassId(0), b"first").unwrap();
        assert_eq!(first[0], mask(&new_key, 0));
        assert_eq!(recv.open(&last).unwrap().payload, b"last");
        assert_eq!(recv.open(&first).unwrap().payload, b"first");
    }

    /// The same class does not show the same byte record after record.
    #[test]
    fn the_class_byte_is_not_sent_in_the_clear() {
        let (mut send, _) = pair();
        let bytes: std::collections::HashSet<u8> = (0..64)
            .map(|_| send.seal(ClassId(0), b"").unwrap()[0])
            .collect();
        assert!(bytes.len() > 16, "{} distinct header bytes", bytes.len());
    }

    /// The first record through a lent direction is the framer's own bytes,
    /// and reading its length spends nothing.
    #[test]
    fn the_first_record_opens_through_a_lent_direction() {
        let mut send = ClassedRecord::new(keyed(), table());
        let mut direction = keyed();
        let wire = send.seal(ClassId(1), b"request").unwrap();
        let t = table();
        assert_eq!(first_record_len(&direction, &t, wire[0]), Ok(wire.len()));
        assert_eq!(
            open_first_record(&mut direction, &t, &wire[..10]),
            Err(ClassedError::Truncated)
        );
        let opened = open_first_record(&mut direction, &t, &wire).unwrap();
        assert_eq!(opened.payload, b"request");
        assert_eq!(direction.opened(), 1);
        // The direction carries on as the session's receiving half.
        let mut recv = ClassedRecord::new(direction, t);
        let wire = send.seal(ClassId(0), b"second").unwrap();
        assert_eq!(recv.open(&wire).unwrap().payload, b"second");
    }

    #[test]
    fn a_table_breaking_a_rule_is_refused() {
        assert_eq!(ClassTable::new(&[]), Err(ClassTableError::RowCount(0)));
        let rows: Vec<usize> = (2..259).collect();
        assert_eq!(ClassTable::new(&rows), Err(ClassTableError::RowCount(257)));
        assert!(ClassTable::new(&rows[..256]).is_ok());
        assert_eq!(ClassTable::new(&[1]), Err(ClassTableError::RowLength(1)));
        assert_eq!(
            ClassTable::new(&[512, 65_536]),
            Err(ClassTableError::RowLength(65_536))
        );
        assert_eq!(ClassTable::new(&[512, 512]), Err(ClassTableError::Order));
        assert_eq!(ClassTable::new(&[600, 512]), Err(ClassTableError::Order));
        assert!(ClassTable::new(&[2]).is_ok());
    }
}
