use std::convert::TryFrom;
use std::ffi::CString;
use std::ops::Range;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;

use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use leansig::signature::{SignatureScheme, SignatureSchemeSecretKey};
use leansig::serialization::Serializable;
use leansig::MESSAGE_LENGTH;

// Signature scheme configuration matching Ream
#[cfg(all(not(test), feature = "signature-scheme-prod"))]
pub type LeanSigScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;
#[cfg(all(not(test), feature = "signature-scheme-prod"))]
pub const SIGNATURE_SIZE: usize = 3112;

#[cfg(all(not(test), feature = "signature-scheme-test"))]
pub type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
#[cfg(all(not(test), feature = "signature-scheme-test"))]
pub const SIGNATURE_SIZE: usize = 2344;

#[cfg(test)]
pub type LeanSigScheme = leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_8::SIGTopLevelTargetSumLifetime8Dim64Base8;
#[cfg(test)]
pub const SIGNATURE_SIZE: usize = 2344;

// Public key size is fixed at 52 bytes (8 + 5 KoalaBear field elements * 4 bytes each)
pub const PUBLIC_KEY_SIZE: usize = 52;

// Type aliases for convenience
type PublicKeyType = <LeanSigScheme as SignatureScheme>::PublicKey;
type SecretKeyType = <LeanSigScheme as SignatureScheme>::SecretKey;
type SignatureType = <LeanSigScheme as SignatureScheme>::Signature;

/// Wrapper for signature scheme secret key
///
/// This is an opaque structure whose fields are not accessible from C code
#[repr(C)]
pub struct PQSignatureSchemeSecretKey {
    _private: [u8; 0],
}

/// Wrapper for signature scheme public key
///
/// This is an opaque structure whose fields are not accessible from C code
#[repr(C)]
pub struct PQSignatureSchemePublicKey {
    _private: [u8; 0],
}

/// Wrapper for signature
///
/// This is an opaque structure whose fields are not accessible from C code
#[repr(C)]
pub struct PQSignature {
    _private: [u8; 0],
}

// Internal wrappers (not exported to C)
struct PQSignatureSchemeSecretKeyInner {
    inner: Box<SecretKeyType>,
}

struct PQSignatureSchemePublicKeyInner {
    inner: Box<PublicKeyType>,
}

struct PQSignatureInner {
    inner: Box<SignatureType>,
}

/// Range representation for C
#[repr(C)]
pub struct PQRange {
    pub start: u64,
    pub end: u64,
}

impl From<Range<u64>> for PQRange {
    fn from(range: Range<u64>) -> Self {
        PQRange {
            start: range.start,
            end: range.end,
        }
    }
}

/// Error codes for signature scheme
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum PQSigningError {
    /// Success (not an error)
    Success = 0,
    /// Failed to encode message after maximum number of attempts
    EncodingAttemptsExceeded = 1,
    /// Invalid pointer (null pointer)
    InvalidPointer = 2,
    /// Invalid message length
    InvalidMessageLength = 3,
    /// Epoch outside supported range
    InvalidEpoch = 4,
    /// Unknown error
    UnknownError = 99,
}

// ============================================================================
// Memory management functions
// ============================================================================

/// Frees memory allocated for secret key
/// # Safety
/// Pointer must be valid and created via pq_key_gen
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_free(key: *mut PQSignatureSchemeSecretKey) {
    if !key.is_null() {
        let _ = Box::from_raw(key as *mut PQSignatureSchemeSecretKeyInner);
    }
}

/// Frees memory allocated for public key
/// # Safety
/// Pointer must be valid and created via pq_key_gen
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_free(key: *mut PQSignatureSchemePublicKey) {
    if !key.is_null() {
        let _ = Box::from_raw(key as *mut PQSignatureSchemePublicKeyInner);
    }
}

/// Frees memory allocated for signature
/// # Safety
/// Pointer must be valid and created via pq_sign
#[no_mangle]
pub unsafe extern "C" fn pq_signature_free(signature: *mut PQSignature) {
    if !signature.is_null() {
        let _ = Box::from_raw(signature as *mut PQSignatureInner);
    }
}

/// Frees memory allocated for error description string
/// # Safety
/// Pointer must be valid and created via pq_error_description
#[no_mangle]
pub unsafe extern "C" fn pq_string_free(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

// ============================================================================
// SignatureSchemeSecretKey functions
// ============================================================================

/// Get key activation interval
/// # Safety
/// Pointer must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_get_activation_interval(
    key: *const PQSignatureSchemeSecretKey,
) -> PQRange {
    if key.is_null() {
        return PQRange { start: 0, end: 0 };
    }
    let key = &*(key as *const PQSignatureSchemeSecretKeyInner);
    key.inner.get_activation_interval().into()
}

/// Get prepared interval of the key
/// # Safety
/// Pointer must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_get_prepared_interval(
    key: *const PQSignatureSchemeSecretKey,
) -> PQRange {
    if key.is_null() {
        return PQRange { start: 0, end: 0 };
    }
    let key = &*(key as *const PQSignatureSchemeSecretKeyInner);
    key.inner.get_prepared_interval().into()
}

/// Advance key preparation to next interval
/// # Safety
/// Pointer must be valid and mutable
#[no_mangle]
pub unsafe extern "C" fn pq_advance_preparation(key: *mut PQSignatureSchemeSecretKey) {
    if key.is_null() {
        return;
    }
    let key = &mut *(key as *mut PQSignatureSchemeSecretKeyInner);
    key.inner.advance_preparation();
}

// ============================================================================
// SignatureScheme functions
// ============================================================================

/// Get maximum lifetime of signature scheme
#[no_mangle]
pub extern "C" fn pq_get_lifetime() -> u64 {
    LeanSigScheme::LIFETIME
}

/// Get signature size in bytes
#[no_mangle]
pub extern "C" fn pq_get_signature_size() -> usize {
    SIGNATURE_SIZE
}

/// Get public key size in bytes
#[no_mangle]
pub extern "C" fn pq_get_public_key_size() -> usize {
    PUBLIC_KEY_SIZE
}

/// Generate key pair (public and secret)
///
/// # Parameters
/// - `activation_epoch`: starting epoch for key activation
/// - `num_active_epochs`: number of active epochs
/// - `pk_out`: pointer to write public key (output)
/// - `sk_out`: pointer to write secret key (output)
///
/// # Returns
/// Error code (Success = 0 on success)
///
/// # Safety
/// Pointers pk_out and sk_out must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_key_gen(
    activation_epoch: usize,
    num_active_epochs: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if pk_out.is_null() || sk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let mut rng = rand::rng();
    let (pk, sk) = LeanSigScheme::key_gen(&mut rng, activation_epoch, num_active_epochs);

    let pk_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
        inner: Box::new(pk),
    });
    let sk_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
        inner: Box::new(sk),
    });

    *pk_out = Box::into_raw(pk_wrapper) as *mut PQSignatureSchemePublicKey;
    *sk_out = Box::into_raw(sk_wrapper) as *mut PQSignatureSchemeSecretKey;

    PQSigningError::Success
}

/// Sign a message
///
/// # Parameters
/// - `sk`: secret key for signing
/// - `epoch`: epoch for which signature is created
/// - `message`: pointer to message
/// - `message_len`: message length (must be MESSAGE_LENGTH = 32)
/// - `signature_out`: pointer to write signature (output)
///
/// # Returns
/// Error code (Success = 0 on success)
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_sign(
    sk: *const PQSignatureSchemeSecretKey,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if sk.is_null() || message.is_null() || signature_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    if message_len != MESSAGE_LENGTH {
        return PQSigningError::InvalidMessageLength;
    }

    let epoch32 = match u32::try_from(epoch) {
        Ok(value) => value,
        Err(_) => return PQSigningError::InvalidEpoch,
    };

    let sk = &*(sk as *const PQSignatureSchemeSecretKeyInner);
    let message_slice = slice::from_raw_parts(message, message_len);

    // Convert slice to fixed-size array
    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message_slice);

    match LeanSigScheme::sign(&sk.inner, epoch32, &message_array) {
        Ok(signature) => {
            let sig_wrapper = Box::new(PQSignatureInner {
                inner: Box::new(signature),
            });
            *signature_out = Box::into_raw(sig_wrapper) as *mut PQSignature;
            PQSigningError::Success
        }
        Err(leansig::signature::SigningError::EncodingAttemptsExceeded { .. }) => {
            PQSigningError::EncodingAttemptsExceeded
        }
    }
}

/// Verify a signature
///
/// # Parameters
/// - `pk`: public key
/// - `epoch`: signature epoch
/// - `message`: pointer to message
/// - `message_len`: message length (must be MESSAGE_LENGTH = 32)
/// - `signature`: signature to verify
///
/// # Returns
/// 1 if signature is valid, 0 if invalid, negative value on error
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_verify(
    pk: *const PQSignatureSchemePublicKey,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature: *const PQSignature,
) -> c_int {
    if pk.is_null() || message.is_null() || signature.is_null() {
        return -1; // Error: invalid pointer
    }

    if message_len != MESSAGE_LENGTH {
        return -2; // Error: invalid message length
    }

    let epoch32 = match u32::try_from(epoch) {
        Ok(value) => value,
        Err(_) => return -3,
    };

    let pk = &*(pk as *const PQSignatureSchemePublicKeyInner);
    let signature = &*(signature as *const PQSignatureInner);
    let message_slice = slice::from_raw_parts(message, message_len);

    // Convert slice to fixed-size array
    let mut message_array = [0u8; MESSAGE_LENGTH];
    message_array.copy_from_slice(message_slice);

    let is_valid = LeanSigScheme::verify(&pk.inner, epoch32, &message_array, &signature.inner);

    if is_valid {
        1
    } else {
        0
    }
}

/// Verify a signature from SSZ-serialized bytes
///
/// This function deserializes the public key and signature from SSZ format
/// (compatible with Ream's leanSig serialization) and verifies the signature.
///
/// # Parameters
/// - `pubkey_bytes`: pointer to SSZ-serialized public key bytes (52 bytes)
/// - `pubkey_len`: length of public key bytes
/// - `epoch`: signature epoch
/// - `message`: pointer to message (must be 32 bytes)
/// - `message_len`: message length (must be MESSAGE_LENGTH = 32)
/// - `signature_bytes`: pointer to SSZ-serialized signature bytes
/// - `signature_len`: length of signature bytes
///
/// # Returns
/// 1 if signature is valid, 0 if invalid, negative value on error
///
/// # Safety
/// All pointers must be valid and point to correctly sized data
#[no_mangle]
pub unsafe extern "C" fn pq_verify_ssz(
    pubkey_bytes: *const u8,
    pubkey_len: usize,
    epoch: u64,
    message: *const u8,
    message_len: usize,
    signature_bytes: *const u8,
    signature_len: usize,
) -> c_int {
    if pubkey_bytes.is_null() || message.is_null() || signature_bytes.is_null() {
        return -1;
    }

    if message_len != MESSAGE_LENGTH {
        return -2;
    }

    if pubkey_len != PUBLIC_KEY_SIZE {
        return -7;
    }

    if signature_len != SIGNATURE_SIZE {
        return -8;
    }

    let epoch32 = match u32::try_from(epoch) {
        Ok(value) => value,
        Err(_) => return -3,
    };

    let pk_data = slice::from_raw_parts(pubkey_bytes, pubkey_len);
    let sig_data = slice::from_raw_parts(signature_bytes, signature_len);
    let msg_data = slice::from_raw_parts(message, message_len);

    let message_array: &[u8; MESSAGE_LENGTH] = match msg_data.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            return -4;
        }
    };

    // Deserialize public key using leanSig's Serializable trait (SSZ format)
    let pk: PublicKeyType = match PublicKeyType::from_bytes(pk_data) {
        Ok(pk) => pk,
        Err(_) => {
            return -5;
        }
    };

    // Deserialize signature using leanSig's Serializable trait (SSZ format)
    let sig: SignatureType = match SignatureType::from_bytes(sig_data) {
        Ok(sig) => sig,
        Err(_) => {
            return -6;
        }
    };

    let is_valid = <LeanSigScheme as SignatureScheme>::verify(&pk, epoch32, message_array, &sig);

    if is_valid {
        1
    } else {
        0
    }
}

// ============================================================================
// Error handling functions
// ============================================================================

/// Get error description string
///
/// # Parameters
/// - `error`: error code
///
/// # Returns
/// Pointer to C-string with error description.
/// Memory must be freed using pq_string_free
///
/// # Safety
/// Returned pointer must be freed by caller
#[no_mangle]
pub extern "C" fn pq_error_description(error: PQSigningError) -> *mut c_char {
    let description = match error {
        PQSigningError::Success => "Success",
        PQSigningError::EncodingAttemptsExceeded => {
            "Failed to encode message after maximum number of attempts"
        }
        PQSigningError::InvalidPointer => "Invalid pointer (null pointer passed)",
        PQSigningError::InvalidMessageLength => {
            "Invalid message length (must be 32 bytes)"
        }
        PQSigningError::InvalidEpoch => "Epoch outside supported range",
        PQSigningError::UnknownError => "Unknown error",
    };

    match CString::new(description) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// Serialization functions - Using SSZ format (leanSig's Serializable trait)
// ============================================================================

/// Serialize secret key to bytes using SSZ format
///
/// # Parameters
/// - `sk`: secret key
/// - `buffer`: buffer for writing
/// - `buffer_len`: buffer size
/// - `written_len`: pointer to write actual data size (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_serialize(
    sk: *const PQSignatureSchemeSecretKey,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if sk.is_null() || buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let sk = &*(sk as *const PQSignatureSchemeSecretKeyInner);

    let bytes = sk.inner.to_bytes();
    if bytes.len() > buffer_len {
        *written_len = bytes.len();
        return PQSigningError::UnknownError; // Buffer too small
    }
    let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    buffer_slice[..bytes.len()].copy_from_slice(&bytes);
    *written_len = bytes.len();
    PQSigningError::Success
}

/// Deserialize secret key from bytes using SSZ format
///
/// # Parameters
/// - `buffer`: buffer with data
/// - `buffer_len`: buffer size
/// - `sk_out`: pointer to write secret key (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if buffer.is_null() || sk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);

    match SecretKeyType::from_bytes(buffer_slice) {
        Ok(sk) => {
            let sk_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
                inner: Box::new(sk),
            });
            *sk_out = Box::into_raw(sk_wrapper) as *mut PQSignatureSchemeSecretKey;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}


/// Serialize public key to bytes using SSZ format
///
/// # Parameters
/// - `pk`: public key
/// - `buffer`: buffer for writing
/// - `buffer_len`: buffer size
/// - `written_len`: pointer to write actual data size (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_serialize(
    pk: *const PQSignatureSchemePublicKey,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if pk.is_null() || buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let pk = &*(pk as *const PQSignatureSchemePublicKeyInner);

    let bytes = pk.inner.to_bytes();
    if bytes.len() > buffer_len {
        *written_len = bytes.len();
        return PQSigningError::UnknownError; // Buffer too small
    }
    let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    buffer_slice[..bytes.len()].copy_from_slice(&bytes);
    *written_len = bytes.len();
    PQSigningError::Success
}

/// Deserialize public key from bytes using SSZ format
///
/// # Parameters
/// - `buffer`: buffer with data
/// - `buffer_len`: buffer size
/// - `pk_out`: pointer to write public key (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
) -> PQSigningError {
    if buffer.is_null() || pk_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);

    match PublicKeyType::from_bytes(buffer_slice) {
        Ok(pk) => {
            let pk_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
                inner: Box::new(pk),
            });
            *pk_out = Box::into_raw(pk_wrapper) as *mut PQSignatureSchemePublicKey;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}


/// Serialize signature to bytes using SSZ format
///
/// # Parameters
/// - `signature`: signature
/// - `buffer`: buffer for writing
/// - `buffer_len`: buffer size
/// - `written_len`: pointer to write actual data size (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_signature_serialize(
    signature: *const PQSignature,
    buffer: *mut u8,
    buffer_len: usize,
    written_len: *mut usize,
) -> PQSigningError {
    if signature.is_null() || buffer.is_null() || written_len.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let signature = &*(signature as *const PQSignatureInner);

    let bytes = signature.inner.to_bytes();
    if bytes.len() > buffer_len {
        *written_len = bytes.len();
        return PQSigningError::UnknownError; // Buffer too small
    }
    let buffer_slice = slice::from_raw_parts_mut(buffer, buffer_len);
    buffer_slice[..bytes.len()].copy_from_slice(&bytes);
    *written_len = bytes.len();
    PQSigningError::Success
}

/// Deserialize signature from bytes using SSZ format
///
/// # Parameters
/// - `buffer`: buffer with data
/// - `buffer_len`: buffer size
/// - `signature_out`: pointer to write signature (output)
///
/// # Returns
/// Error code
///
/// # Safety
/// All pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn pq_signature_deserialize(
    buffer: *const u8,
    buffer_len: usize,
    signature_out: *mut *mut PQSignature,
) -> PQSigningError {
    if buffer.is_null() || signature_out.is_null() {
        return PQSigningError::InvalidPointer;
    }

    let buffer_slice = slice::from_raw_parts(buffer, buffer_len);

    match SignatureType::from_bytes(buffer_slice) {
        Ok(signature) => {
            let sig_wrapper = Box::new(PQSignatureInner {
                inner: Box::new(signature),
            });
            *signature_out = Box::into_raw(sig_wrapper) as *mut PQSignature;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}

// ============================================================================
// JSON deserialization functions
// ============================================================================

/// Deserialize public key from JSON
///
/// # Parameters
/// - `json`: pointer to UTF-8 JSON buffer
/// - `json_len`: buffer size
/// - `pk_out`: pointer to write public key (output)
///
/// # Returns
/// Error code
#[no_mangle]
pub unsafe extern "C" fn pq_public_key_from_json(
    json: *const u8,
    json_len: usize,
    pk_out: *mut *mut PQSignatureSchemePublicKey,
) -> PQSigningError {
    if json.is_null() || pk_out.is_null() || json_len == 0 {
        return PQSigningError::InvalidPointer;
    }

    let json_slice = std::slice::from_raw_parts(json, json_len);
    let json_str = match std::str::from_utf8(json_slice) {
        Ok(s) => s,
        Err(_) => return PQSigningError::UnknownError,
    };

    match serde_json::from_str::<PublicKeyType>(json_str) {
        Ok(pk) => {
            let pk_wrapper = Box::new(PQSignatureSchemePublicKeyInner {
                inner: Box::new(pk),
            });
            *pk_out = Box::into_raw(pk_wrapper) as *mut PQSignatureSchemePublicKey;
            PQSigningError::Success
        }
        Err(_) => PQSigningError::UnknownError,
    }
}

/// Deserialize secret key from JSON
///
/// # Parameters
/// - `json`: pointer to UTF-8 JSON buffer
/// - `json_len`: buffer size
/// - `sk_out`: pointer to write secret key (output)
///
/// # Returns
/// Error code
#[no_mangle]
pub unsafe extern "C" fn pq_secret_key_from_json(
    json: *const u8,
    json_len: usize,
    sk_out: *mut *mut PQSignatureSchemeSecretKey,
) -> PQSigningError {
    if json.is_null() || sk_out.is_null() || json_len == 0 {
        return PQSigningError::InvalidPointer;
    }

    let json_slice = std::slice::from_raw_parts(json, json_len);
    let json_str = match std::str::from_utf8(json_slice) {
        Ok(s) => s,
        Err(_) => {
            return PQSigningError::UnknownError;
        }
    };

    match serde_json::from_str::<SecretKeyType>(json_str) {
        Ok(sk) => {
            let sk_wrapper = Box::new(PQSignatureSchemeSecretKeyInner {
                inner: Box::new(sk),
            });
            *sk_out = Box::into_raw(sk_wrapper) as *mut PQSignatureSchemeSecretKey;
            PQSigningError::Success
        }
        Err(_) => {
            PQSigningError::UnknownError
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen_and_sign() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();

            // Key generation
            let result = pq_key_gen(0, 100, &mut pk, &mut sk);
            assert_eq!(result, PQSigningError::Success);
            assert!(!pk.is_null());
            assert!(!sk.is_null());

            // Check intervals
            let activation = pq_get_activation_interval(sk);
            assert!(activation.start < activation.end);

            let prepared = pq_get_prepared_interval(sk);
            assert!(prepared.start < prepared.end);

            // Sign message
            let message = [0u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            let sign_result = pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature);
            assert_eq!(sign_result, PQSigningError::Success);
            assert!(!signature.is_null());

            // Verify signature
            let verify_result = pq_verify(pk, 10, message.as_ptr(), MESSAGE_LENGTH, signature);
            assert_eq!(verify_result, 1);

            // Cleanup
            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    fn test_error_description() {
        let desc = pq_error_description(PQSigningError::Success);
        assert!(!desc.is_null());
        unsafe {
            pq_string_free(desc);
        }
    }

    #[test]
    fn test_invalid_pointers() {
        unsafe {
            // Test with null pointers
            let result = pq_key_gen(0, 100, ptr::null_mut(), ptr::null_mut());
            assert_eq!(result, PQSigningError::InvalidPointer);

            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let result = pq_key_gen(0, 100, &mut pk, ptr::null_mut());
            assert_eq!(result, PQSigningError::InvalidPointer);

            // pq_sign with null pointers
            let message = [0u8; MESSAGE_LENGTH];
            let result = pq_sign(
                ptr::null(),
                0,
                message.as_ptr(),
                MESSAGE_LENGTH,
                ptr::null_mut(),
            );
            assert_eq!(result, PQSigningError::InvalidPointer);

            // pq_verify with null pointers
            let verify_result = pq_verify(ptr::null(), 0, message.as_ptr(), MESSAGE_LENGTH, ptr::null());
            assert_eq!(verify_result, -1);

            // Freeing null pointers should not panic
            pq_secret_key_free(ptr::null_mut());
            pq_public_key_free(ptr::null_mut());
            pq_signature_free(ptr::null_mut());
            pq_string_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_invalid_message_length() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            pq_key_gen(0, 100, &mut pk, &mut sk);

            // Test with incorrect message length for signing
            let short_message = [0u8; 16]; // Incorrect length
            let mut signature: *mut PQSignature = ptr::null_mut();
            let result = pq_sign(sk, 10, short_message.as_ptr(), 16, &mut signature);
            assert_eq!(result, PQSigningError::InvalidMessageLength);

            // Create valid signature
            let valid_message = [0u8; MESSAGE_LENGTH];
            let result = pq_sign(sk, 10, valid_message.as_ptr(), MESSAGE_LENGTH, &mut signature);
            assert_eq!(result, PQSigningError::Success);

            // Test verify with incorrect message length
            let verify_result = pq_verify(pk, 10, short_message.as_ptr(), 16, signature);
            assert_eq!(verify_result, -2);

            // Test verify with long message
            let long_message = [0u8; 64];
            let verify_result = pq_verify(pk, 10, long_message.as_ptr(), 64, signature);
            assert_eq!(verify_result, -2);

            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    fn test_signature_verification_with_wrong_data() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            pq_key_gen(0, 100, &mut pk, &mut sk);

            let message = [1u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature);

            // Check with correct data
            let result = pq_verify(pk, 10, message.as_ptr(), MESSAGE_LENGTH, signature);
            assert_eq!(result, 1);

            // Check with wrong epoch
            let result = pq_verify(pk, 11, message.as_ptr(), MESSAGE_LENGTH, signature);
            assert_eq!(result, 0);

            // Check with modified message
            let wrong_message = [2u8; MESSAGE_LENGTH];
            let result = pq_verify(pk, 10, wrong_message.as_ptr(), MESSAGE_LENGTH, signature);
            assert_eq!(result, 0);

            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    fn test_advance_preparation() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            pq_key_gen(0, 100, &mut pk, &mut sk);

            let initial_prepared = pq_get_prepared_interval(sk);
            assert!(initial_prepared.start < initial_prepared.end);

            // Advance preparation
            pq_advance_preparation(sk);
            let new_prepared = pq_get_prepared_interval(sk);

            // New interval should be shifted
            assert!(new_prepared.start > initial_prepared.start);
            assert!(new_prepared.end > initial_prepared.end);

            // Advance again
            pq_advance_preparation(sk);
            let newer_prepared = pq_get_prepared_interval(sk);
            assert!(newer_prepared.start > new_prepared.start);

            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    fn test_serialization_deserialization() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            pq_key_gen(0, 100, &mut pk, &mut sk);

            let message = [42u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature);

            // Test public key serialization/deserialization
            let mut pk_buffer = vec![0u8; 10000];
            let mut pk_written = 0;
            let result = pq_public_key_serialize(
                pk,
                pk_buffer.as_mut_ptr(),
                pk_buffer.len(),
                &mut pk_written,
            );
            assert_eq!(result, PQSigningError::Success);
            assert_eq!(pk_written, PUBLIC_KEY_SIZE);

            let mut pk_restored: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let result = pq_public_key_deserialize(
                pk_buffer.as_ptr(),
                pk_written,
                &mut pk_restored,
            );
            assert_eq!(result, PQSigningError::Success);
            assert!(!pk_restored.is_null());

            // Check that restored key works
            let verify_result = pq_verify(pk_restored, 10, message.as_ptr(), MESSAGE_LENGTH, signature);
            assert_eq!(verify_result, 1);

            // Test secret key serialization/deserialization
            let mut sk_buffer = vec![0u8; 1000000];
            let mut sk_written = 0;
            let result = pq_secret_key_serialize(
                sk,
                sk_buffer.as_mut_ptr(),
                sk_buffer.len(),
                &mut sk_written,
            );
            assert_eq!(result, PQSigningError::Success);
            assert!(sk_written > 0);

            let mut sk_restored: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            let result = pq_secret_key_deserialize(
                sk_buffer.as_ptr(),
                sk_written,
                &mut sk_restored,
            );
            assert_eq!(result, PQSigningError::Success);
            assert!(!sk_restored.is_null());

            // Check that restored key can sign
            let mut new_signature: *mut PQSignature = ptr::null_mut();
            let result = pq_sign(sk_restored, 20, message.as_ptr(), MESSAGE_LENGTH, &mut new_signature);
            assert_eq!(result, PQSigningError::Success);

            // Test signature serialization/deserialization
            let mut sig_buffer = vec![0u8; 100000];
            let mut sig_written = 0;
            let result = pq_signature_serialize(
                signature,
                sig_buffer.as_mut_ptr(),
                sig_buffer.len(),
                &mut sig_written,
            );
            assert_eq!(result, PQSigningError::Success);
            assert_eq!(sig_written, SIGNATURE_SIZE);

            let mut sig_restored: *mut PQSignature = ptr::null_mut();
            let result = pq_signature_deserialize(
                sig_buffer.as_ptr(),
                sig_written,
                &mut sig_restored,
            );
            assert_eq!(result, PQSigningError::Success);
            assert!(!sig_restored.is_null());

            // Check restored signature
            let verify_result = pq_verify(pk, 10, message.as_ptr(), MESSAGE_LENGTH, sig_restored);
            assert_eq!(verify_result, 1);

            // Cleanup
            pq_signature_free(sig_restored);
            pq_signature_free(new_signature);
            pq_signature_free(signature);
            pq_secret_key_free(sk_restored);
            pq_secret_key_free(sk);
            pq_public_key_free(pk_restored);
            pq_public_key_free(pk);
        }
    }

    #[test]
    fn test_ssz_verification() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            pq_key_gen(0, 100, &mut pk, &mut sk);

            let message = [42u8; MESSAGE_LENGTH];
            let mut signature: *mut PQSignature = ptr::null_mut();
            pq_sign(sk, 10, message.as_ptr(), MESSAGE_LENGTH, &mut signature);

            // Serialize public key
            let mut pk_buffer = vec![0u8; PUBLIC_KEY_SIZE];
            let mut pk_written = 0;
            pq_public_key_serialize(pk, pk_buffer.as_mut_ptr(), pk_buffer.len(), &mut pk_written);

            // Serialize signature
            let mut sig_buffer = vec![0u8; SIGNATURE_SIZE];
            let mut sig_written = 0;
            pq_signature_serialize(signature, sig_buffer.as_mut_ptr(), sig_buffer.len(), &mut sig_written);

            // Verify using SSZ bytes
            let result = pq_verify_ssz(
                pk_buffer.as_ptr(),
                pk_written,
                10,
                message.as_ptr(),
                MESSAGE_LENGTH,
                sig_buffer.as_ptr(),
                sig_written,
            );
            assert_eq!(result, 1);

            // Verify with wrong epoch should fail
            let result = pq_verify_ssz(
                pk_buffer.as_ptr(),
                pk_written,
                11,
                message.as_ptr(),
                MESSAGE_LENGTH,
                sig_buffer.as_ptr(),
                sig_written,
            );
            assert_eq!(result, 0);

            // Cleanup
            pq_signature_free(signature);
            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    fn test_multiple_signatures() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            pq_key_gen(0, 100, &mut pk, &mut sk);

            // Sign several different messages with different epochs
            for epoch in [5, 10, 15, 20, 25] {
                let message = [epoch as u8; MESSAGE_LENGTH];
                let mut signature: *mut PQSignature = ptr::null_mut();

                let result = pq_sign(sk, epoch, message.as_ptr(), MESSAGE_LENGTH, &mut signature);
                assert_eq!(result, PQSigningError::Success);

                let verify_result = pq_verify(pk, epoch, message.as_ptr(), MESSAGE_LENGTH, signature);
                assert_eq!(verify_result, 1);

                // Verification with wrong epoch should fail
                let wrong_verify = pq_verify(pk, epoch + 1, message.as_ptr(), MESSAGE_LENGTH, signature);
                assert_eq!(wrong_verify, 0);

                pq_signature_free(signature);
            }

            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    fn test_get_sizes() {
        assert_eq!(pq_get_signature_size(), SIGNATURE_SIZE);
        assert_eq!(pq_get_public_key_size(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_activation_and_prepared_intervals() {
        unsafe {
            let activation_epoch = 10;
            let num_active_epochs = 50;

            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            pq_key_gen(activation_epoch, num_active_epochs, &mut pk, &mut sk);

            let activation = pq_get_activation_interval(sk);
            let prepared = pq_get_prepared_interval(sk);

            // Activation interval should contain prepared interval
            assert!(activation.start <= prepared.start);
            assert!(activation.end >= prepared.end);

            // Check interval sizes
            let activation_size = activation.end - activation.start;
            let prepared_size = prepared.end - prepared.start;

            assert!(activation_size >= prepared_size);

            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }

    #[test]
    fn test_all_error_descriptions() {
        // Check all error variants
        let errors = vec![
            PQSigningError::Success,
            PQSigningError::EncodingAttemptsExceeded,
            PQSigningError::InvalidPointer,
            PQSigningError::InvalidMessageLength,
            PQSigningError::InvalidEpoch,
            PQSigningError::UnknownError,
        ];

        for error in errors {
            let desc = pq_error_description(error);
            assert!(!desc.is_null());
            unsafe {
                let c_str = std::ffi::CStr::from_ptr(desc);
                let desc_str = c_str.to_str().unwrap();
                assert!(!desc_str.is_empty());
                pq_string_free(desc);
            }
        }
    }

    #[test]
    fn test_serialization_buffer_too_small() {
        unsafe {
            let mut pk: *mut PQSignatureSchemePublicKey = ptr::null_mut();
            let mut sk: *mut PQSignatureSchemeSecretKey = ptr::null_mut();
            pq_key_gen(0, 100, &mut pk, &mut sk);

            // Try to serialize into too small buffer
            let mut small_buffer = [0u8; 10];
            let mut written = 0;
            let result = pq_public_key_serialize(
                pk,
                small_buffer.as_mut_ptr(),
                small_buffer.len(),
                &mut written,
            );

            // Should be error, but written should contain required size
            assert_eq!(result, PQSigningError::UnknownError);
            assert!(written > small_buffer.len());

            pq_public_key_free(pk);
            pq_secret_key_free(sk);
        }
    }
}
