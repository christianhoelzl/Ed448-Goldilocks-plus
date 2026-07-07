//! X448 Diffie-Hellman key agreement.
//!
//! This module implements the X448 function from RFC7748 using the crate's
//! Curve448 Montgomery arithmetic.

use crate::MontgomeryPoint;
use core::{
    fmt,
    hash::{Hash, Hasher},
};
use subtle::ConstantTimeEq;
#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Length of an X448 scalar, public key, or shared secret in bytes.
pub const X448_LENGTH: usize = 56;

/// The X448 basepoint, for use with the bare, byte-oriented [`x448`] function.
pub const X448_BASEPOINT_BYTES: [u8; X448_LENGTH] = [
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Clone)]
struct Scalar {
    bytes: [u8; X448_LENGTH],
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar").finish_non_exhaustive()
    }
}

impl From<[u8; X448_LENGTH]> for Scalar {
    fn from(bytes: [u8; X448_LENGTH]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl Scalar {
    fn from_bytes(mut bytes: [u8; X448_LENGTH]) -> Self {
        bytes[0] &= 0xfc;
        bytes[55] |= 0x80;
        Self { bytes }
    }

    fn bits(&self) -> [bool; 448] {
        let mut bits = [false; 448];
        for (byte_idx, byte) in self.bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                bits[8 * byte_idx + bit_idx] = ((byte >> bit_idx) & 1) == 1;
            }
        }
        bits
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for Scalar {}

#[cfg(feature = "zeroize")]
impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An X448 public key.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PublicKey {
    point: MontgomeryPoint,
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl From<[u8; X448_LENGTH]> for PublicKey {
    /// Given a byte array, construct an X448 public key.
    fn from(bytes: [u8; X448_LENGTH]) -> Self {
        Self {
            point: MontgomeryPoint(bytes),
        }
    }
}

impl From<&StaticSecret> for PublicKey {
    /// Given an X448 static secret key, compute its corresponding public key.
    fn from(secret: &StaticSecret) -> Self {
        Self {
            point: MontgomeryPoint(x448(secret.bytes, X448_BASEPOINT_BYTES)),
        }
    }
}

impl From<&EphemeralSecret> for PublicKey {
    /// Given an X448 ephemeral secret key, compute its corresponding public key.
    fn from(secret: &EphemeralSecret) -> Self {
        Self {
            point: MontgomeryPoint(x448(secret.bytes, X448_BASEPOINT_BYTES)),
        }
    }
}

impl From<&ReusableSecret> for PublicKey {
    /// Given an X448 reusable secret key, compute its corresponding public key.
    fn from(secret: &ReusableSecret) -> Self {
        Self {
            point: MontgomeryPoint(x448(secret.bytes, X448_BASEPOINT_BYTES)),
        }
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    pub fn to_bytes(&self) -> [u8; X448_LENGTH] {
        self.point.0
    }

    /// View this public key as bytes.
    pub fn as_bytes(&self) -> &[u8; X448_LENGTH] {
        self.point.as_bytes()
    }
}

impl AsRef<[u8]> for PublicKey {
    /// View this public key as a byte array.
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A reusable X448 private key.
///
/// This type is intended for long-term secret keys. Prefer [`EphemeralSecret`]
/// when the protocol does not require key reuse.
#[derive(Clone)]
pub struct StaticSecret {
    bytes: [u8; X448_LENGTH],
}

impl fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticSecret").finish_non_exhaustive()
    }
}

impl From<[u8; X448_LENGTH]> for StaticSecret {
    /// Load a secret key from a byte array.
    fn from(bytes: [u8; X448_LENGTH]) -> Self {
        Self { bytes }
    }
}

impl StaticSecret {
    /// Generate a new static secret with the supplied RNG.
    pub fn random_from_rng<T: rand_core::CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; X448_LENGTH];
        csprng.fill_bytes(&mut bytes);
        Self::from(bytes)
    }

    /// Perform a Diffie-Hellman key agreement.
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret {
            point: MontgomeryPoint(x448(self.bytes, their_public.to_bytes())),
        }
    }

    /// Extract this key's bytes for serialization.
    pub fn to_bytes(&self) -> [u8; X448_LENGTH] {
        self.bytes
    }

    /// View this key as a byte array.
    pub fn as_bytes(&self) -> &[u8; X448_LENGTH] {
        &self.bytes
    }
}

impl AsRef<[u8]> for StaticSecret {
    /// View this key as a byte array.
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for StaticSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for StaticSecret {}

#[cfg(feature = "zeroize")]
impl Drop for StaticSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A single-use X448 private key.
pub struct EphemeralSecret {
    bytes: [u8; X448_LENGTH],
}

impl fmt::Debug for EphemeralSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralSecret").finish_non_exhaustive()
    }
}

impl From<[u8; X448_LENGTH]> for EphemeralSecret {
    /// Load an ephemeral secret key from a byte array.
    fn from(bytes: [u8; X448_LENGTH]) -> Self {
        Self { bytes }
    }
}

impl EphemeralSecret {
    /// Generate a new ephemeral secret with the supplied RNG.
    pub fn random_from_rng<T: rand_core::CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; X448_LENGTH];
        csprng.fill_bytes(&mut bytes);
        Self::from(bytes)
    }

    /// Perform a Diffie-Hellman key agreement.
    pub fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret {
            point: MontgomeryPoint(x448(self.bytes, their_public.to_bytes())),
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for EphemeralSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for EphemeralSecret {}

#[cfg(feature = "zeroize")]
impl Drop for EphemeralSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A reusable X448 private key.
///
/// This type can be used more than once but is intentionally not serializable
/// through dedicated methods.
#[derive(Clone)]
pub struct ReusableSecret {
    bytes: [u8; X448_LENGTH],
}

impl fmt::Debug for ReusableSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReusableSecret").finish_non_exhaustive()
    }
}

impl From<[u8; X448_LENGTH]> for ReusableSecret {
    /// Load a reusable secret key from a byte array.
    fn from(bytes: [u8; X448_LENGTH]) -> Self {
        Self { bytes }
    }
}

impl ReusableSecret {
    /// Generate a new reusable secret with the supplied RNG.
    pub fn random_from_rng<T: rand_core::CryptoRng>(mut csprng: T) -> Self {
        let mut bytes = [0u8; X448_LENGTH];
        csprng.fill_bytes(&mut bytes);
        Self::from(bytes)
    }

    /// Perform a Diffie-Hellman key agreement.
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret {
            point: MontgomeryPoint(x448(self.bytes, their_public.to_bytes())),
        }
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for ReusableSecret {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for ReusableSecret {}

#[cfg(feature = "zeroize")]
impl Drop for ReusableSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// An X448 shared secret.
pub struct SharedSecret {
    point: MontgomeryPoint,
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret").finish_non_exhaustive()
    }
}

impl SharedSecret {
    /// Convert this shared secret to a byte array.
    pub fn to_bytes(&self) -> [u8; X448_LENGTH] {
        self.point.0
    }

    /// View this shared secret as bytes.
    pub fn as_bytes(&self) -> &[u8; X448_LENGTH] {
        self.point.as_bytes()
    }

    /// Return whether this shared secret did not result from non-contributory behavior.
    #[must_use]
    pub fn was_contributory(&self) -> bool {
        !bool::from(self.point.0.ct_eq(&[0u8; X448_LENGTH]))
    }
}

impl AsRef<[u8]> for SharedSecret {
    /// View this shared secret key as a byte array.
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.point.0.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SharedSecret {}

#[cfg(feature = "zeroize")]
impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Compute the raw X448 function from RFC7748.
pub fn x448(scalar: [u8; X448_LENGTH], u_coordinate: [u8; X448_LENGTH]) -> [u8; X448_LENGTH] {
    let scalar = Scalar::from_bytes(scalar);
    let point = MontgomeryPoint(u_coordinate);
    point.mul_bits(scalar.bits()).0
}

#[cfg(test)]
mod tests;
