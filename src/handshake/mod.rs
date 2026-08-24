//use p256::elliptic_curve::AffinePoint;
use crate::CertificateVerify;
use crate::TlsError;
use crate::config::Certificate;
use crate::crypto_traits::TlsHash;
use crate::extensions::extension_data::signature_algorithms::SignatureScheme;
use crate::handshake::certificate::CertificateRef;
use crate::handshake::certificate_request::CertificateRequestRef;
use crate::handshake::certificate_verify::CertificateVerifyRef;
use crate::handshake::client_hello::ClientHello;
use crate::handshake::encrypted_extensions::EncryptedExtensions;
use crate::handshake::finished::Finished;
use crate::handshake::new_session_ticket::NewSessionTicket;
use crate::handshake::server_hello::ServerHello;
use crate::key_schedule::ProviderHashOutputSize;
use crate::parse_buffer::{ParseBuffer, ParseError};
use crate::{CryptoProvider, buffer::CryptoBuffer, key_schedule::WriteKeySchedule};
use core::fmt::{Debug, Formatter};

pub mod binder;
pub mod certificate;
pub mod certificate_request;
pub mod certificate_verify;
pub mod client_hello;
pub mod encrypted_extensions;
pub mod finished;
pub mod new_session_ticket;
pub mod server_hello;

const LEGACY_VERSION: u16 = 0x0303;

type Random = [u8; 32];

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl HandshakeType {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        match buf.read_u8()? {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            13 => Ok(HandshakeType::CertificateRequest),
            15 => Ok(HandshakeType::CertificateVerify),
            20 => Ok(HandshakeType::Finished),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(ParseError::InvalidData),
        }
    }

    #[allow(dead_code)]
    pub fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self as u8).map_err(|_| TlsError::EncodeError)
    }
}

// Minimal RNG for PSK binder computation (only used when PSK is present)
#[allow(dead_code)]
struct DummyRng;
impl rand_core::RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        dest.fill(0);
        Ok(())
    }
}
impl rand_core::CryptoRng for DummyRng {}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientHandshake<'config, 'a, Provider>
where
    Provider: CryptoProvider,
{
    ClientHello(ClientHello<'config, Provider::CipherSuite>),
    ClientCertificate(CertificateRef<'a>),
    ClientCertificateVerify(CertificateVerify),
    Finished(Finished<ProviderHashOutputSize<Provider>>),
}

impl<Provider> ClientHandshake<'_, '_, Provider>
where
    Provider: CryptoProvider,
{
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn handshake_type(&self) -> HandshakeType {
        match self {
            ClientHandshake::ClientHello(_) => HandshakeType::ClientHello,
            ClientHandshake::Finished(_) => HandshakeType::Finished,
            ClientHandshake::ClientCertificate(_) => HandshakeType::Certificate,
            ClientHandshake::ClientCertificateVerify(_) => HandshakeType::CertificateVerify,
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        match self {
            ClientHandshake::ClientHello(inner) => inner.encode(buf),
            ClientHandshake::Finished(inner) => inner.encode(buf),
            ClientHandshake::ClientCertificate(inner) => inner.encode(buf),
            ClientHandshake::ClientCertificateVerify(inner) => inner.encode(buf),
        }
    }

    pub fn finalize(
        &self,
        buf: &mut CryptoBuffer,
        transcript: &mut Provider::Hash,
        write_key_schedule: &mut WriteKeySchedule<Provider>,
        provider: Option<&mut Provider>,
    ) -> Result<(), TlsError> {
        if let ClientHandshake::ClientHello(_hello) = self {
            let psk_binder = write_key_schedule
                .create_psk_binder(transcript, provider.ok_or(TlsError::InternalError)?)
                .map_err(|_| TlsError::InvalidHandshake)?;
            psk_binder.encode(buf)?;
        }
        Ok(())
    }

    pub fn finalize_encrypted(buf: &mut CryptoBuffer, transcript: &mut Provider::Hash) {
        let mut transcript_clone = transcript.clone();
        transcript_clone.update(buf.as_slice());
        *transcript = transcript_clone;
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerHandshake<'a, Provider: CryptoProvider> {
    ServerHello(ServerHello<'a>),
    EncryptedExtensions(EncryptedExtensions<'a>),
    Certificate(CertificateRef<'a>),
    CertificateVerify(CertificateVerifyRef<'a>),
    CertificateRequest(CertificateRequestRef<'a>),
    Finished(Finished<ProviderHashOutputSize<Provider>>),
    NewSessionTicket(NewSessionTicket<'a>),
}

impl<Provider: CryptoProvider> ServerHandshake<'_, Provider> {
    #[allow(dead_code)]
    #[allow(dead_code)]
    pub fn handshake_type(&self) -> HandshakeType {
        match self {
            ServerHandshake::ServerHello(_) => HandshakeType::ServerHello,
            ServerHandshake::EncryptedExtensions(_) => HandshakeType::EncryptedExtensions,
            ServerHandshake::Certificate(_) => HandshakeType::Certificate,
            ServerHandshake::CertificateRequest(_) => HandshakeType::CertificateRequest,
            ServerHandshake::CertificateVerify(_) => HandshakeType::CertificateVerify,
            ServerHandshake::Finished(_) => HandshakeType::Finished,
            ServerHandshake::NewSessionTicket(_) => HandshakeType::NewSessionTicket,
        }
    }
}

impl<Provider: CryptoProvider> Debug for ServerHandshake<'_, Provider> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ServerHandshake::ServerHello(inner) => Debug::fmt(inner, f),
            ServerHandshake::EncryptedExtensions(inner) => Debug::fmt(inner, f),
            ServerHandshake::Certificate(inner) => Debug::fmt(inner, f),
            ServerHandshake::CertificateRequest(inner) => Debug::fmt(inner, f),
            ServerHandshake::CertificateVerify(inner) => Debug::fmt(inner, f),
            ServerHandshake::Finished(inner) => Debug::fmt(inner, f),
            ServerHandshake::NewSessionTicket(inner) => Debug::fmt(inner, f),
        }
    }
}

#[cfg(feature = "defmt")]
impl<'a, Provider: CryptoProvider> defmt::Format for ServerHandshake<'a, Provider> {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            ServerHandshake::ServerHello(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::EncryptedExtensions(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::Certificate(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::CertificateRequest(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::CertificateVerify(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::Finished(inner) => defmt::write!(f, "{}", inner),
            ServerHandshake::NewSessionTicket(inner) => defmt::write!(f, "{}", inner),
        }
    }
}

impl<'a, Provider: CryptoProvider> ServerHandshake<'a, Provider> {
    pub fn read(
        buf: &mut ParseBuffer<'a>,
        digest: &mut Provider::Hash,
    ) -> Result<ServerHandshake<'a, Provider>, TlsError> {
        let content_length = buf.read_u24().map_err(|_| TlsError::InvalidHandshake)?;
        let handshake_type = HandshakeType::parse(buf).map_err(|_| TlsError::InvalidHandshake)?;

        let mut handshake = match handshake_type {
            HandshakeType::ServerHello => ServerHandshake::ServerHello(ServerHello::parse(buf)?),
            HandshakeType::NewSessionTicket => {
                ServerHandshake::NewSessionTicket(NewSessionTicket::parse(buf)?)
            }
            HandshakeType::EncryptedExtensions => {
                ServerHandshake::EncryptedExtensions(EncryptedExtensions::parse(buf)?)
            }
            HandshakeType::Certificate => ServerHandshake::Certificate(CertificateRef::parse(buf)?),
            HandshakeType::CertificateRequest => {
                ServerHandshake::CertificateRequest(CertificateRequestRef::parse(buf)?)
            }
            HandshakeType::CertificateVerify => {
                ServerHandshake::CertificateVerify(CertificateVerifyRef::parse(buf)?)
            }
            HandshakeType::Finished => {
                ServerHandshake::Finished(Finished::parse(buf, content_length)?)
            }
            _ => {
                return Err(TlsError::InvalidHandshake);
            }
        };

        if let ServerHandshake::Finished(finished) = &mut handshake {
            let mut hash = digest.clone();
            hash.update(buf.as_slice());
            let mut out = Default::default();
            hash.finalize_into(&mut out);
            finished.hash = Some(out);
        } else {
            digest.update(buf.as_slice());
        }

        Ok(handshake)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(dead_code)]
pub struct ClientCertificate<'a> {
    pub certificate: Certificate<&'a [u8]>,
}

#[allow(dead_code)]
impl<'a> ClientCertificate<'a> {
    pub fn new(certificate: Certificate<&'a [u8]>) -> Self {
        Self { certificate }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        self.certificate.encode(buf)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(dead_code)]
pub struct ClientCertificateVerify<'a> {
    pub signature: &'a [u8],
    pub signature_scheme: SignatureScheme,
}

#[allow(dead_code)]
impl<'a> ClientCertificateVerify<'a> {
    pub fn new(signature: &'a [u8], signature_scheme: SignatureScheme) -> Self {
        Self {
            signature,
            signature_scheme,
        }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.signature_scheme.as_u16())
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(self.signature)
            .map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }
}
