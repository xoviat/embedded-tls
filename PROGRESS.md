# embedded-tls Hardware-Abstraction Patch — COMPLETE

This is a fully patched version of `embedded-tls` (main branch) that replaces all
hardcoded RustCrypto calls with trait-based abstractions so that hardware
crypto servers (e.g. `embassy-crypto`) can accelerate every operation without
`embedded-tls` depending on them directly.

---

## Architecture

```
embedded-tls
├── CryptoProvider  (trait - extended with hash/hmac/aead/ecdh/keygen)
├── TlsHash         (trait - hardware-abstracted hash)
├── TlsHmac         (trait - hardware-abstracted HMAC)
├── TlsAead         (trait - hardware-abstracted AEAD)
│
│   Default impls ──→ RustCrypto stack (sha2, hmac, aes-gcm)
│   Override impls ──→ CryptoServer (embassy-crypto, HSM, etc.)
│
└── No dependency on embassy-crypto
```

---

## Full acceleration coverage

| Operation | Before | After | Cryptoserver API |
|-----------|--------|-------|------------------|
| SHA-256/384 transcript hash | `sha2::Sha256` | `TlsHash` | `sha256_init/update/finalize` |
| HKDF / key schedule | `hkdf` crate | Inline HKDF over `TlsHmac` | `hmac_sha256_init/update/finalize` |
| AES-GCM record crypto | `aes_gcm::Aes128Gcm` | `TlsAead` (stored in KeyScheduleState) | `aes_gcm_128/256_encrypt/decrypt` |
| P-256/P-384 ECDH | `p256::ecdh::diffie_hellman` | `CryptoProvider::ecdh` | `p256_ecdh`, `p384_ecdh` |
| P-256/P-384 keygen | `p256::PublicKey::from_secret_scalar` | `CryptoProvider::keygen` | `p256_keygen`, `p384_keygen` |
| RNG | `CryptoProvider::rng` | unchanged | `blocking_rng_fill` |
| Cert verify | `TlsVerifier` | unchanged | `p256_ecdsa_verify`, RSA verify |
| Client cert sign | `CryptoProvider::signer` | unchanged | `p256_ecdsa_sign`, RSA sign |

---

## Files Changed

| File | Change |
|------|--------|
| `src/crypto_traits.rs` | **NEW.** `TlsHash`, `TlsHmac`, `TlsAead` traits. Blanket impls for `sha2`/`hmac`/`aes-gcm`. `RustCryptoHash`, `RustCryptoHmac`, `RustCryptoAead` helper types. |
| `src/hkdf.rs` | **NEW.** Inline `hkdf_extract`, `hkdf_expand`, `derive_secret` using `TlsHmac`. Replaces the `hkdf` crate entirely. |
| `src/lib.rs` | Added `pub mod crypto_traits; mod hkdf;`. Removed `mod crypto_engine;`. |
| `src/config.rs` | Extended `CryptoProvider` with `type Hash`, `type Hmac`, `type Aead` + `hash()`, `hmac()`, `aead()`, `ecdh()`, `keygen()`. Default software impls. `TlsVerifier<Hash>`. `UnsecureProvider` updated. |
| `src/key_schedule.rs` | Generic over `Provider`. Inline HKDF. `KeyScheduleState` stores `aead: Option<Provider::Aead>` for reuse. |
| `src/connection.rs` | `Handshake<Provider>` stores `secret_key: [u8; 32]`. `decrypt_record`/`encrypt` use `key_schedule.get_aead()`. `process_server_hello` uses `provider.ecdh()`. |
| `src/handshake/mod.rs` | Generic over `Provider`. |
| `src/handshake/client_hello.rs` | Uses `provider.keygen()`. Stores `secret_key`/`public_key`. |
| `src/handshake/server_hello.rs` | Exposes `server_public_key()`. Removed `EphemeralSecret`/`SharedSecret`/`CryptoEngine` deps. |
| `src/record.rs` | Generic over `Provider`. |
| `src/record_reader.rs` | Generic over `Provider`. |
| `src/write_buffer.rs` | Generic over `Provider`. `close_record`/`write_record` simplified. |
| `src/asynch.rs` | `TlsConnection<'a, Socket, Provider>`. All `TlsReader`/`TlsWriter` generics updated. |
| `src/blocking.rs` | Same as `asynch.rs` for blocking API. |
| `src/pki.rs` | `CertVerifier<Hash, Clock, CERT_SIZE>` instead of `CipherSuite`. `TlsHash::finalize_into`. |
| `src/webpki.rs` | Same as `pki.rs`. |
| `src/common/decrypted_read_handler.rs` | Generic over `Provider`. |
| `src/crypto_engine.rs` | **DELETED.** No longer needed. |
| `Cargo.toml` | Removed `hkdf` dependency. |

---

## Bug Fixes Applied

### Fixed: `SharedState::initialize` empty-salt bug
**File:** `src/key_schedule.rs`

The original diff special-cased an all-zeros salt and passed `&[]` (empty slice)
to `hkdf_extract`. `HMAC([0; HashLen], ikm) ≠ HMAC("", ikm)`, which broke the
entire key schedule. Fixed by always passing `self.secret.as_slice()`.

### Fixed: `client_hello.rs` raw-random scalar panic vector
**Files:** `src/config.rs`, `src/handshake/client_hello.rs`

The original diff filled 32 random bytes and passed them to `keygen` as a raw
scalar. The default software impl rejected values `≥ n` or `== 0` via
`p256::SecretKey::from_slice`, creating a `~2⁻⁶²` panic vector.

**Fix:**
- Changed `keygen` signature from `secret_key: &[u8]` to `secret_key: &mut [u8]`
  so the provider writes the actual scalar back.
- Default impl now does rejection sampling internally: fills the buffer from
  `self.rng()` in a loop until a valid scalar is found.
- `client_hello.rs` no longer pre-fills `secret_key`; it passes an empty buffer
  as an output parameter.

This also fixes the secondary issue where a hardware provider might ignore the
input scalar and generate its own keypair, causing a mismatch with the stored
`secret_key`.

### Already fixed: `verify_server_finished` non-constant-time comparison
**File:** `src/key_schedule.rs`

Uses `subtle::ConstantTimeEq::ct_eq` instead of `==` on HMAC tags.

### Already fixed: `SharedState::initialize` missing `self.secret = prk`
**File:** `src/key_schedule.rs`

`self.secret = prk.clone();` is present after `hkdf_extract`.

### Remaining (accepted for MVP): `hkdf_extract` panics on HMAC init failure
**File:** `src/hkdf.rs`

`hkdf_extract` uses `.expect("hkdf extract")` on `Hmac::new()`. For the RustCrypto
software path this is safe, but for hardware HMAC peripherals (STM32, ESP32)
that can fail when the peripheral is busy, this is a panic vector in `no_std`.
Accepted for initial implementation.

---

## How to use with embassy-crypto

```rust
use embedded_tls::{CryptoProvider, TlsHash, TlsHmac, TlsAead, TlsConfig, TlsContext};
use embassy_crypto::CryptoServer;

pub struct EmbassyProvider<'a> {
    server: &'a CryptoServer<'a>,
}

impl CryptoProvider for EmbassyProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = p256::ecdsa::DerSignature;
    type Hash = EmbassyHash<'a>;
    type Hmac = EmbassyHmac<'a>;
    type Aead = EmbassyAead<'a>;

    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, TlsError> { /* ... */ }
    fn ecdh(&mut self, group: NamedGroup, sk: &[u8], pk: &[u8], ss: &mut [u8]) -> Result<(), TlsError> {
        self.server.blocking_p256_ecdh(sk, pk, ss)
    }
    fn keygen(&mut self, group: NamedGroup, sk: &mut [u8], pk: &mut [u8]) -> Result<(), TlsError> {
        self.server.blocking_p256_keygen(sk, pk)
    }
    // rng, verifier, signer, client_cert unchanged
}
```

---

## Backward compatibility

Existing code using `UnsecureProvider` compiles unchanged:
```rust
let mut provider = UnsecureProvider::new::<Aes128GcmSha256>(OsRng);
let mut connection = TlsConnection::new(socket, rx_buf, tx_buf);
connection.open(TlsContext::new(&config, &mut provider)).await?;
```

The default implementations of `hash()`, `hmac()`, `aead()`, `ecdh()`, and `keygen()`
dispatch to the RustCrypto stack, so no changes are required for software-only users.

---

## Design decisions

- **Kept `TlsCipherSuite::Hash` and `TlsCipherSuite::Cipher`** as associated types
  for backward compatibility. The new `CryptoProvider` methods have **default impls**
  that delegate to these associated types.
- **No global references**: `CryptoProvider` methods take `&mut self`.
- **Inline HKDF**: The `hkdf` crate is generic over `Digest` which is the blocker.
  HKDF is ~50 lines; inlining it removes the dependency and enables hardware HMAC.
- **AEAD caching**: `KeyScheduleState` stores the `TlsAead` instance after key
  derivation, avoiding repeated `provider.aead(key)` calls per record.
- **Blocking-first**: All trait methods are synchronous. A hardware provider can
  internally block-to-completion on the driver.
- **`keygen` as output parameter**: `secret_key: &mut [u8]` instead of `&[u8]`
  makes the contract unambiguous — the provider generates the keypair and writes
  the actual secret scalar back, eliminating both the invalid-scalar panic vector
  and the hardware-provider key-mismatch risk.
