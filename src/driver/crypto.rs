//! Encryption schemes supported by Discord's secure RTP negotiation.
use byteorder::{NetworkEndian, WriteBytesExt};
#[cfg(any(feature = "receive", test))]
use crypto_secretbox::Tag;
use crypto_secretbox::{
    aead::{AeadInPlace, Error as CryptoError},
    Nonce,
    SecretBox,
    XSalsa20Poly1305 as Cipher,
};
use discortp::{rtp::RtpPacket, MutablePacket};
use rand::Rng;
use std::{num::Wrapping, str::FromStr};
use crate::error::ConnectionError;

#[cfg(test)]
pub const KEY_SIZE: usize = SecretBox::<()>::KEY_SIZE;
pub const NONCE_SIZE: usize = SecretBox::<()>::NONCE_SIZE;
pub const TAG_SIZE: usize = SecretBox::<()>::TAG_SIZE;

/// Encryption schemes used for voice packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default, Hash)]
#[non_exhaustive]
pub enum CryptoMode {
    #[default]
    /// Discord's currently preferred non-E2EE encryption scheme.
    ///
    /// Packets are encrypted and decrypted using the `AES256GCM` encryption scheme.
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Encrypted content begins *after* the RTP header, following the SRTP specification.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    Aes256Gcm,
    /// A fallback non-E2EE encryption scheme.
    ///
    /// Packets are encrypted and decrypted using the `XChaCha20Poly1305` encryption scheme.
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Encrypted content begins *after* the RTP header, following the SRTP specification.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    XChaCha20Poly1305,
    #[deprecated(
        since = "0.4.4",
        note = "This voice encryption mode will no longer be accepted by Discord\
                as of 2024-11-18. This variant will be removed in `v0.5`.",
    )]
    /// The RTP header is used as the source of nonce bytes for the packet.
    ///
    /// Equivalent to a nonce of at most 48b (6B) at no extra packet overhead:
    /// the RTP sequence number and timestamp are the varying quantities.
    Normal,
    #[deprecated(
        since = "0.4.4",
        note = "This voice encryption mode will no longer be accepted by Discord\
                as of 2024-11-18. This variant will be removed in `v0.5`.",
    )]
    /// An additional random 24B suffix is used as the source of nonce bytes for the packet.
    /// This is regenerated randomly for each packet.
    ///
    /// Full nonce width of 24B (192b), at an extra 24B per packet (~1.2 kB/s).
    Suffix,
    #[deprecated(
        since = "0.4.4",
        note = "This voice encryption mode will no longer be accepted by Discord\
                as of 2024-11-18. This variant will be removed in `v0.5`.",
    )]
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// Nonce width of 4B (32b), at an extra 4B per packet (~0.2 kB/s).
    Lite,
}

impl From<CryptoState> for CryptoMode {
    #[allow(deprecated)]
    fn from(val: CryptoState) -> Self {
        match val {
            CryptoState::Aes256Gcm(_) => Self::Aes256Gcm,
            CryptoState::XChaCha20Poly1305(_) => Self::XChaCha20Poly1305,
            CryptoState::Normal => Self::Normal,
            CryptoState::Suffix => Self::Suffix,
            CryptoState::Lite(_) => Self::Lite,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum EncryptionAlgorithm {
    Aes256,
    XChaCha20Poly1305,
    XSalsa20Poly1305,
}

/// The input string could not be parsed as an encryption scheme supported by songbird.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UnrecognisedCryptoMode;

impl FromStr for CryptoMode {
    type Err = UnrecognisedCryptoMode;

    #[allow(deprecated)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aead_aes256_gcm_rtpsize" => Ok(Self::Aes256Gcm),
            "aead_xchacha20_poly1305_rtpsize" => Ok(Self::XChaCha20Poly1305),
            "xsalsa20_poly1305" => Ok(Self::Normal),
            "xsalsa20_poly1305_suffix" => Ok(Self::Suffix),
            "xsalsa20_poly1305_lite" => Ok(Self::Lite),
            _ => Err(UnrecognisedCryptoMode)
        }
    }
}

#[allow(deprecated)]
impl CryptoMode {
    /// Returns the underlying crypto algorithm used by a given [`CryptoMode`].
    #[must_use]
    pub(crate) fn algorithm(&self) -> EncryptionAlgorithm {
        match self {
            CryptoMode::Aes256Gcm => EncryptionAlgorithm::Aes256,
            CryptoMode::XChaCha20Poly1305 => EncryptionAlgorithm::XChaCha20Poly1305,
            CryptoMode::Normal | CryptoMode::Suffix | CryptoMode::Lite
                => EncryptionAlgorithm::XSalsa20Poly1305,
        }
    }

    /// Returns a local priority score for a given [`CryptoMode`].
    ///
    /// Higher values are preferred.
    #[must_use]
    pub(crate) fn priority(&self) -> u64 {
        match self {
            CryptoMode::Aes256Gcm => 4,
            CryptoMode::XChaCha20Poly1305 => 3,
            CryptoMode::Normal => 2,
            CryptoMode::Suffix => 1,
            CryptoMode::Lite => 0,
        }
    }

    /// Returns the best available crypto mode, given the `modes` offered by the Discord voice server.
    ///
    /// If `preferred` is set and the mode exists in the server's supported algorithms, then that
    /// mode will be chosen. Otherwise we select the highest-scoring option which is mutually understood.
    #[must_use]
    pub(crate) fn negotiate<It, T>(modes: It, preferred: Option<Self>) -> Result<Self, ConnectionError>
        where
            T: for<'a> AsRef<&'a str>,
            It: IntoIterator<Item = T>,
    {
        let mut best = None;
        for el in modes {
            let Ok(el) = CryptoMode::from_str(el.as_ref()) else {
                // Unsupported mode. Ignore.
                continue;
            };

            let Some((curr_best, curr_score)) = best else {
                best = Some((el, el.priority()));
                continue;
            };

            let el_priority = el.priority();

            // Not quite right. Think on it.
            if let Some(preferred) = preferred {
                if el == preferred {
                    best = Some((el, el_priority));
                }
            } else if el.{

            }
        }

        best.map(|(v, score)| v).ok_or(ConnectionError::CryptoModeUnavailable)
    }

    /// Returns the name of a mode as it will appear during negotiation.
    #[must_use]
    pub fn to_request_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aead_aes256_gcm_rtpsize",
            Self::XChaCha20Poly1305 => "aead_xchacha20_poly1305_rtpsize",
            Self::Normal => "xsalsa20_poly1305",
            Self::Suffix => "xsalsa20_poly1305_suffix",
            Self::Lite => "xsalsa20_poly1305_lite",
        }
    }

    /// Returns the number of bytes each nonce is stored as within
    /// a packet.
    #[must_use]
    pub fn nonce_size(self) -> usize {
        match self {
            Self::Aes256Gcm | Self::XChaCha20Poly1305 | Self::Lite => 4,
            Self::Normal => RtpPacket::minimum_packet_size(),
            Self::Suffix => NONCE_SIZE,
        }
    }

    /// Returns the number of bytes occupied by the encryption scheme
    /// which fall before the payload.
    #[must_use]
    pub fn payload_prefix_len() -> usize {
        // TODO: this may be totally wrong.
        TAG_SIZE
    }

    /// Returns the number of bytes occupied by the encryption scheme
    /// which fall after the payload.
    #[must_use]
    pub fn payload_suffix_len(self) -> usize {
        match self {
            Self::Normal => 0,
            Self::Suffix | Self::Lite => self.nonce_size(),
        }
    }

    /// Calculates the number of additional bytes required compared
    /// to an unencrypted payload.
    #[must_use]
    pub fn payload_overhead(self) -> usize {
        Self::payload_prefix_len() + self.payload_suffix_len()
    }

    /// Extracts the byte slice in a packet used as the nonce, and the remaining mutable
    /// portion of the packet.
    fn nonce_slice<'a>(
        self,
        header: &'a [u8],
        body: &'a mut [u8],
    ) -> Result<(&'a [u8], &'a mut [u8]), CryptoError> {
        match self {
            Self::Normal => Ok((header, body)),
            Self::Suffix | Self::Lite => {
                let len = body.len();
                if len < self.payload_suffix_len() {
                    Err(CryptoError)
                } else {
                    let (body_left, nonce_loc) = body.split_at_mut(len - self.payload_suffix_len());
                    Ok((&nonce_loc[..self.nonce_size()], body_left))
                }
            },
        }
    }

    #[cfg(any(feature = "receive", test))]
    /// Decrypts a Discord RT(C)P packet using the given key.
    ///
    /// If successful, this returns the number of bytes to be ignored from the
    /// start and end of the packet payload.
    #[inline]
    pub(crate) fn decrypt_in_place(
        self,
        packet: &mut impl MutablePacket,
        cipher: &Cipher,
    ) -> Result<(usize, usize), CryptoError> {
        // FIXME on next: packet encrypt/decrypt should use an internal error
        //  to denote "too small" vs. "opaque".
        let header_len = packet.packet().len() - packet.payload().len();
        let (header, body) = packet.packet_mut().split_at_mut(header_len);
        let (slice_to_use, body_remaining) = self.nonce_slice(header, body)?;

        let mut nonce = Nonce::default();
        let nonce_slice = if slice_to_use.len() == NONCE_SIZE {
            Nonce::from_slice(&slice_to_use[..NONCE_SIZE])
        } else {
            let max_bytes_avail = slice_to_use.len();
            nonce[..self.nonce_size().min(max_bytes_avail)].copy_from_slice(slice_to_use);
            &nonce
        };

        let body_start = Self::payload_prefix_len();
        let body_tail = self.payload_suffix_len();

        if body_start > body_remaining.len() {
            return Err(CryptoError);
        }

        let (tag_bytes, data_bytes) = body_remaining.split_at_mut(body_start);
        let tag = Tag::from_slice(tag_bytes);

        cipher
            .decrypt_in_place_detached(nonce_slice, b"", data_bytes, tag)
            .map(|()| (body_start, body_tail))
    }

    /// Encrypts a Discord RT(C)P packet using the given key.
    ///
    /// Use of this requires that the input packet has had a nonce generated in the correct location,
    /// and `payload_len` specifies the number of bytes after the header including this nonce.
    #[inline]
    pub fn encrypt_in_place(
        self,
        packet: &mut impl MutablePacket,
        cipher: &Cipher,
        payload_len: usize,
    ) -> Result<(), CryptoError> {
        let header_len = packet.packet().len() - packet.payload().len();
        let (header, body) = packet.packet_mut().split_at_mut(header_len);
        let (slice_to_use, body_remaining) = self.nonce_slice(header, &mut body[..payload_len])?;

        let mut nonce = Nonce::default();
        let nonce_slice = if slice_to_use.len() == NONCE_SIZE {
            Nonce::from_slice(&slice_to_use[..NONCE_SIZE])
        } else {
            nonce[..self.nonce_size()].copy_from_slice(slice_to_use);
            &nonce
        };

        // body_remaining is now correctly truncated by this point.
        // the true_payload to encrypt follows after the first TAG_LEN bytes.
        let tag =
            cipher.encrypt_in_place_detached(nonce_slice, b"", &mut body_remaining[TAG_SIZE..])?;
        body_remaining[..TAG_SIZE].copy_from_slice(&tag[..]);

        Ok(())
    }
}

/// State used in nonce generation for the `XSalsa20Poly1305` encryption variants
/// in [`CryptoMode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum CryptoState {
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The last used nonce is stored.
    Aes256Gcm(Wrapping<u32>),
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The last used nonce is stored.
    XChaCha20Poly1305(Wrapping<u32>),
    /// The RTP header is used as the source of nonce bytes for the packet.
    ///
    /// No state is required.
    Normal,
    /// An additional random 24B suffix is used as the source of nonce bytes for the packet.
    /// This is regenerated randomly for each packet.
    ///
    /// No state is required.
    Suffix,
    /// An additional random 4B suffix is used as the source of nonce bytes for the packet.
    /// This nonce value increments by `1` with each packet.
    ///
    /// The last used nonce is stored.
    Lite(Wrapping<u32>),
}

impl From<CryptoMode> for CryptoState {
    fn from(val: CryptoMode) -> Self {
        match val {
            CryptoMode::Aes256Gcm => CryptoState::Lite(Wrapping(rand::random::<u32>()))
            CryptoMode::XChaCha20Poly1305 => CryptoState::Lite(Wrapping(rand::random::<u32>()))
            CryptoMode::Normal => CryptoState::Normal,
            CryptoMode::Suffix => CryptoState::Suffix,
            CryptoMode::Lite => CryptoState::Lite(Wrapping(rand::random::<u32>())),
        }
    }
}

impl CryptoState {
    /// Writes packet nonce into the body, if required, returning the new length.
    pub fn write_packet_nonce(
        &mut self,
        packet: &mut impl MutablePacket,
        payload_end: usize,
    ) -> usize {
        let mode = self.kind();
        let endpoint = payload_end + mode.payload_suffix_len();

        match self {
            Self::Suffix => {
                rand::thread_rng().fill(&mut packet.payload_mut()[payload_end..endpoint]);
            },
            Self::Lite(mut i) => {
                (&mut packet.payload_mut()[payload_end..endpoint])
                    .write_u32::<NetworkEndian>(i.0)
                    .expect(
                        "Nonce size is guaranteed to be sufficient to write u32 for lite tagging.",
                    );
                i += Wrapping(1);
            },
            _ => {},
        }

        endpoint
    }

    /// Returns the underlying (stateless) type of the active crypto mode.
    #[must_use]
    pub fn kind(self) -> CryptoMode {
        CryptoMode::from(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto_secretbox::KeyInit;
    use discortp::rtp::MutableRtpPacket;

    #[test]
    fn small_packet_decrypts_error() {
        let mut buf = [0u8; MutableRtpPacket::minimum_packet_size()];
        let modes = [CryptoMode::Normal, CryptoMode::Suffix, CryptoMode::Lite];
        let mut pkt = MutableRtpPacket::new(&mut buf[..]).unwrap();

        let cipher = Cipher::new_from_slice(&[1u8; KEY_SIZE]).unwrap();

        for mode in modes {
            // AIM: should error, and not panic.
            assert!(mode.decrypt_in_place(&mut pkt, &cipher).is_err());
        }
    }

    #[test]
    fn symmetric_encrypt_decrypt() {
        const TRUE_PAYLOAD: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut buf = [0u8; MutableRtpPacket::minimum_packet_size()
            + TRUE_PAYLOAD.len()
            + TAG_SIZE
            + NONCE_SIZE];
        let modes = [CryptoMode::Normal, CryptoMode::Lite, CryptoMode::Suffix];
        let cipher = Cipher::new_from_slice(&[7u8; KEY_SIZE]).unwrap();

        for mode in modes {
            buf.fill(0);

            let mut pkt = MutableRtpPacket::new(&mut buf[..]).unwrap();
            let mut crypto_state = CryptoState::from(mode);
            let payload = pkt.payload_mut();
            payload[TAG_SIZE..TAG_SIZE + TRUE_PAYLOAD.len()].copy_from_slice(&TRUE_PAYLOAD[..]);

            let final_payload_size =
                crypto_state.write_packet_nonce(&mut pkt, TAG_SIZE + TRUE_PAYLOAD.len());

            let enc_succ = mode.encrypt_in_place(&mut pkt, &cipher, final_payload_size);

            assert!(enc_succ.is_ok());

            let final_pkt_len = MutableRtpPacket::minimum_packet_size() + final_payload_size;
            let mut pkt = MutableRtpPacket::new(&mut buf[..final_pkt_len]).unwrap();

            assert!(mode.decrypt_in_place(&mut pkt, &cipher).is_ok());
        }
    }
}
