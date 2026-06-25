//! FCMP++ Bulletproof+ **crypto** re-export, retained after the FCMP++ proof
//! *serializer* types were removed (un-vendor slice 1). The canonical genesis proof
//! framing lives in the Shekyl-owned `shekyl-wire` crate (opaque length-prefixed proof
//! bytes; see `GENESIS_TX_WIRE_FORMAT.md` §6 Q6); only the Bulletproof+ crypto the
//! tx-builder / signer still construct against remains re-exported here.

pub use shekyl_bulletproofs as bulletproofs;
