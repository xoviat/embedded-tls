use crate::buffer::CryptoBuffer;
use crate::TlsError;
use digest::{Output, OutputSizeUser};

#[derive(Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PskBinder<Hash: OutputSizeUser> {
    pub verify: Output<Hash>,
}

#[cfg(feature = "defmt")]
impl<Hash: OutputSizeUser> defmt::Format for PskBinder<Hash> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "PskBinder {{ verify: {:x?} }}", self.verify.as_slice())
    }
}

#[cfg(not(feature = "defmt"))]
impl<Hash: OutputSizeUser> core::fmt::Debug for PskBinder<Hash> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PskBinder")
            .field("verify", &self.verify.as_slice())
            .finish()
    }
}

impl<Hash: OutputSizeUser> PskBinder<Hash> {
    pub fn new(verify: Output<Hash>) -> Self {
        Self { verify }
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push(self.verify.as_slice().len() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(self.verify.as_slice())
            .map_err(|_| TlsError::EncodeError)
    }
}
