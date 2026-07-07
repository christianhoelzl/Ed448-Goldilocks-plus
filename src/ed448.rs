//! Ed448 signing and verification.
//!
//! This module exposes the crate's Ed448 signing API from an algorithm-specific
//! path while preserving the existing top-level exports.

#[cfg(feature = "pkcs8")]
pub use crate::sign::{ALGORITHM_ID, ALGORITHM_OID, KeypairBytes, PublicKeyBytes, pkcs8};
pub use crate::sign::{
    Context, PreHash, PreHasherXmd, PreHasherXof, SecretKey, Signature, SigningError, SigningKey,
    VerifyingKey, crypto_signature,
};
pub use crate::{KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

#[cfg(test)]
mod tests;
