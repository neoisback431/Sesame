// SPDX-License-Identifier: Apache-2.0
//! Jetons de session portail et chiffrement des cookies applicatifs au repos.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::secret::{ExposeSecret, SecretString};

const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("clé de chiffrement invalide : 32 octets encodés en base64 attendus")]
    InvalidKey,
    #[error("déchiffrement impossible")]
    Decrypt,
}

/// Chiffre (AES-256-GCM) les jars de cookies applicatifs stockés dans le magasin de sessions.
pub struct CookieCipher {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for CookieCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CookieCipher(***)")
    }
}

impl CookieCipher {
    pub fn from_base64(key: &SecretString) -> Result<Self, CryptoError> {
        let bytes = Zeroizing::new(
            STANDARD
                .decode(key.expose_secret().trim())
                .map_err(|_| CryptoError::InvalidKey)?,
        );
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        let cipher = Aes256Gcm::new_from_slice(&bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { cipher })
    }

    /// Renvoie `nonce || chiffré`. `aad` lie le chiffré à son contexte (session, appli).
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .expect("AES-GCM ne peut échouer qu'au-delà de 64 Gio");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if data.len() < NONCE_LEN {
            return Err(CryptoError::Decrypt);
        }
        let (nonce, ciphertext) = data.split_at(NONCE_LEN);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Decrypt)
    }
}

/// Nouveau jeton de session portail : 256 bits aléatoires, base64url.
pub fn new_token() -> SecretString {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(bytes.as_mut());
    SecretString::from(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}

/// Empreinte stockée à la place du jeton (SHA-256, hexadécimal).
pub fn hash_token(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher() -> CookieCipher {
        CookieCipher::from_base64(&SecretString::from(STANDARD.encode([7u8; 32]))).unwrap()
    }

    #[test]
    fn roundtrip_and_aad_binding() {
        let c = cipher();
        let data = c.encrypt(b"SESSID=abc", b"s1|app");
        assert!(!data.windows(3).any(|w| w == b"abc"));
        assert_eq!(c.decrypt(&data, b"s1|app").unwrap().as_slice(), b"SESSID=abc");
        assert!(c.decrypt(&data, b"s2|app").is_err());
        assert!(c.decrypt(&data[..5], b"s1|app").is_err());
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(CookieCipher::from_base64(&SecretString::from("court")).is_err());
        assert!(CookieCipher::from_base64(&SecretString::from(STANDARD.encode([1u8; 16]))).is_err());
        assert_eq!(format!("{:?}", cipher()), "CookieCipher(***)");
    }

    #[test]
    fn tokens_are_random_and_hashed() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_eq!(a.expose_secret().len(), 43);
        let h = hash_token(a.expose_secret());
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_token(a.expose_secret()));
    }
}
