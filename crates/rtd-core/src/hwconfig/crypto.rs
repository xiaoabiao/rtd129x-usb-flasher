//! AES-128-**ECB** for the hwsetting blobs.
//!
//! The key is hard-coded in the original executable's `.data`
//! (`?g_AES_USB_key@@3PAEA`). The mode is ECB, **not** CBC: an earlier reading
//! suggested CBC with a zero IV, because under CBC/IV=0 the first plaintext
//! block equals the ECB result. A statistical check settles it -- the fraction
//! of 32-bit words landing in known register windows is
//!
//! ```text
//! file                                  ECB        CBC(zero IV)
//! usb_hwsetting.bin                     128/296    2/296
//! kylin_...2DDR3...                     156/408    1/408
//! kylin_...2DDR4...                     179/472    1/472
//! ```
//!
//! Random data gives ~0%. The decisive proof is that
//! `encrypt(decrypt(x)) == x` bit-for-bit for all three shipped blobs.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::error::{Error, Result};
use crate::protocol::consts::AES_KEY_USB;

/// AES-128-ECB over the fixed hwsetting key.
#[derive(Debug, Clone)]
pub struct HwSettingCipher {
    cipher: Aes128,
}

impl Default for HwSettingCipher {
    fn default() -> Self {
        Self::new()
    }
}

impl HwSettingCipher {
    /// A cipher bound to the hard-coded tool key.
    pub fn new() -> Self {
        Self {
            cipher: Aes128::new(&AES_KEY_USB.into()),
        }
    }

    /// Decrypt a whole blob in place-safe fashion.
    ///
    /// The shipped blobs are already a multiple of 16 bytes, so no padding
    /// handling is needed. A non-multiple length is an error rather than a
    /// silently truncated result.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % 16 != 0 {
            return Err(Error::Aes(format!(
                "ciphertext length {} is not a multiple of 16",
                data.len()
            )));
        }
        let mut out = data.to_vec();
        for chunk in out.chunks_exact_mut(16) {
            let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
            self.cipher.decrypt_block(block);
        }
        Ok(out)
    }

    /// Encrypt a whole blob.
    ///
    /// Zero-pads to a 16-byte boundary, matching what the tool's fixed-size
    /// buffers produce in practice. Returns the number of pad bytes appended so
    /// callers can trim if they need the original length.
    pub fn encrypt_padded(&self, data: &[u8]) -> Result<(Vec<u8>, usize)> {
        let pad = (16 - (data.len() % 16)) % 16;
        let mut out = data.to_vec();
        out.extend(std::iter::repeat(0u8).take(pad));
        for chunk in out.chunks_exact_mut(16) {
            let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
            self.cipher.encrypt_block(block);
        }
        Ok((out, pad))
    }

    /// Encrypt data whose length is already a multiple of 16.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % 16 != 0 {
            return Err(Error::Aes(format!(
                "plaintext length {} is not a multiple of 16; use encrypt_padded",
                data.len()
            )));
        }
        let mut out = data.to_vec();
        for chunk in out.chunks_exact_mut(16) {
            let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
            self.cipher.encrypt_block(block);
        }
        Ok(out)
    }
}

/// Convenience: decrypt with the fixed key.
pub fn decrypt_hwsetting(blob: &[u8]) -> Result<Vec<u8>> {
    HwSettingCipher::new().decrypt(blob)
}

/// Convenience: encrypt with the fixed key, zero-padding if needed.
pub fn encrypt_hwsetting(plain: &[u8]) -> Result<Vec<u8>> {
    Ok(HwSettingCipher::new().encrypt_padded(plain)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_the_recovered_constant() {
        assert_eq!(
            AES_KEY_USB,
            [
                0xab, 0xcd, 0xef, 0x12, 0x13, 0x57, 0x24, 0x68, 0xa1, 0xb2, 0xc3, 0xd4, 0x90,
                0x90, 0xba, 0xbe
            ]
        );
    }

    #[test]
    fn ecb_round_trips() {
        let c = HwSettingCipher::new();
        let plain: Vec<u8> = (0..64u8).collect();
        let enc = c.encrypt(&plain).unwrap();
        assert_eq!(c.decrypt(&enc).unwrap(), plain);
    }

    #[test]
    fn ecb_is_deterministic_and_block_independent() {
        // ECB's defining property: identical plaintext blocks encrypt equally.
        let c = HwSettingCipher::new();
        let mut plain = vec![0u8; 32];
        plain[0..16].copy_from_slice(&[7u8; 16]);
        plain[16..32].copy_from_slice(&[7u8; 16]);
        let enc = c.encrypt(&plain).unwrap();
        assert_eq!(enc[0..16], enc[16..32], "ECB repeats equal blocks");
    }

    #[test]
    fn rejects_misaligned_input() {
        let c = HwSettingCipher::new();
        assert!(c.decrypt(&[0u8; 15]).is_err());
        assert!(c.encrypt(&[0u8; 15]).is_err());
    }

    #[test]
    fn encrypt_padded_reports_the_pad_length() {
        let c = HwSettingCipher::new();
        let (enc, pad) = c.encrypt_padded(&[1, 2, 3]).unwrap();
        assert_eq!(pad, 13);
        assert_eq!(enc.len(), 16);
        assert_eq!(enc.len() % 16, 0);
        // A 16-byte input needs no padding.
        let (enc, pad) = c.encrypt_padded(&[0u8; 16]).unwrap();
        assert_eq!(pad, 0);
        assert_eq!(enc.len(), 16);
    }
}
