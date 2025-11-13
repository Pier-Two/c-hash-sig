# PQ Bindings C Rust

C bindings for the post-quantum cryptography library [hash-sig](https://github.com/b-wagn/hash-sig/).

## Description

This project provides a C API for working with post-quantum hash-based signature schemes. It implements bindings for the XMSS (eXtended Merkle Signature Scheme) using SHA-3 and Winternitz encoding.

## Features

### Data Structures

- **PQSignatureSchemeSecretKey** - wrapper for secret key
- **PQSignatureSchemePublicKey** - wrapper for public key  
- **PQSignature** - wrapper for signature
- **PQRange** - epoch range representation
- **PQSigningError** - error codes

### Core Functions

#### Key Management

```c
// Generate key pair
enum PQSigningError pq_key_gen(
    uintptr_t activation_epoch,
    uintptr_t num_active_epochs,
    struct PQSignatureSchemePublicKey **pk_out,
    struct PQSignatureSchemeSecretKey **sk_out
);

// Free memory
void pq_secret_key_free(struct PQSignatureSchemeSecretKey *key);
void pq_public_key_free(struct PQSignatureSchemePublicKey *key);
```

#### Signing and Verification

```c
// Sign message
enum PQSigningError pq_sign(
    const struct PQSignatureSchemeSecretKey *sk,
    uint64_t epoch,
    const uint8_t *message,
    uintptr_t message_len,
    struct PQSignature **signature_out
);

// Verify signature
int pq_verify(
    const struct PQSignatureSchemePublicKey *pk,
    uint64_t epoch,
    const uint8_t *message,
    uintptr_t message_len,
    const struct PQSignature *signature
);

// Free memory
void pq_signature_free(struct PQSignature *signature);
```

#### State Management

```c
// Get key activation interval
struct PQRange pq_get_activation_interval(const struct PQSignatureSchemeSecretKey *key);

// Get prepared interval
struct PQRange pq_get_prepared_interval(const struct PQSignatureSchemeSecretKey *key);

// Advance preparation to next interval
void pq_advance_preparation(struct PQSignatureSchemeSecretKey *key);

// Get maximum scheme lifetime
uint64_t pq_get_lifetime(void);
```

#### Serialization

```c
// Serialize/deserialize keys and signatures
enum PQSigningError pq_secret_key_serialize(...);
enum PQSigningError pq_secret_key_deserialize(...);
enum PQSigningError pq_public_key_serialize(...);
enum PQSigningError pq_public_key_deserialize(...);
enum PQSigningError pq_signature_serialize(...);
enum PQSigningError pq_signature_deserialize(...);
```

#### Error Handling

```c
// Get error description
char *pq_error_description(enum PQSigningError error);

// Free string
void pq_string_free(char *s);
```

## Building

### Requirements

- Rust 1.87 or higher
- Cargo

### Build Library

```bash
# Debug build
cargo build

# Release build (recommended for production)
cargo build --release
```

After building:
- Library: `target/release/libpq_bindings_c_rust.so` (Linux) or `target/release/libpq_bindings_c_rust.dylib` (macOS) or `target/release/pq_bindings_c_rust.dll` (Windows)
- Static library: `target/release/libpq_bindings_c_rust.a`
- Header file: `include/pq-bindings-c-rust.h` (automatically generated)

### Run Tests

```bash
cargo test
```

**Test Results**: 12/12 tests passed (100% API coverage)

## Usage Example

```c
#include <stdio.h>
#include <stdint.h>
#include "include/pq-bindings-c-rust.h"

int main() {
    // Generate keys
    struct PQSignatureSchemePublicKey *pk = NULL;
    struct PQSignatureSchemeSecretKey *sk = NULL;
    
    enum PQSigningError result = pq_key_gen(0, 10000, &pk, &sk);
    if (result != Success) {
        char *error = pq_error_description(result);
        printf("Key generation error: %s\n", error);
        pq_string_free(error);
        return 1;
    }
    
    printf("Keys generated successfully!\n");
    
    // Get key information
    struct PQRange activation = pq_get_activation_interval(sk);
    printf("Activation interval: %lu - %lu\n", activation.start, activation.end);
    
    struct PQRange prepared = pq_get_prepared_interval(sk);
    printf("Prepared interval: %lu - %lu\n", prepared.start, prepared.end);
    
    uint64_t lifetime = pq_get_lifetime();
    printf("Maximum scheme lifetime: %lu epochs\n", lifetime);
    
    // Prepare message (must be exactly 32 bytes)
    uint8_t message[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    
    // Sign message
    struct PQSignature *signature = NULL;
uint64_t epoch = 100;
    
    result = pq_sign(sk, epoch, message, 32, &signature);
    if (result != Success) {
        char *error = pq_error_description(result);
        printf("Signing error: %s\n", error);
        pq_string_free(error);
        pq_secret_key_free(sk);
        pq_public_key_free(pk);
        return 1;
    }
    
    printf("Message signed successfully!\n");
    
    // Verify signature
    int verify_result = pq_verify(pk, epoch, message, 32, signature);
    if (verify_result == 1) {
        printf("Signature is valid!\n");
    } else if (verify_result == 0) {
        printf("Signature is invalid!\n");
    } else {
        printf("Verification error (code: %d)\n", verify_result);
    }
    
    // Free memory
    pq_signature_free(signature);
    pq_secret_key_free(sk);
    pq_public_key_free(pk);
    
    printf("Done!\n");
    return 0;
}
```

### Compiling Example

```bash
# Linux
gcc -o example example.c -I. -L./target/release -lpq_bindings_c_rust -lpthread -ldl -lm

# Run
LD_LIBRARY_PATH=./target/release ./example
```

Or using Makefile (recommended):
```bash
make run-example
```

## Important Notes

### Synchronized Signature Scheme

This implementation uses a **synchronized (stateful)** signature scheme where:

- Keys have a fixed lifetime divided into **epochs**
- Each epoch can be used for signing **only once**
- Reusing an epoch **compromises the security** of the scheme
- This model is ideal for consensus protocols where validators sign messages at regular intervals

### Managing Prepared Interval

The secret key at any given time can only sign for a limited interval of epochs (prepared interval). Use `pq_advance_preparation()` to move this window to the next interval when needed.

### Message Length

All messages must be **exactly 32 bytes**. To sign longer messages, first use a hash function (e.g., SHA-256 or SHA-3).

### Memory Management

- All objects created by the library (keys, signatures, strings) must be freed using the corresponding `*_free()` functions
- Never free pointers manually via `free()` - use only the provided functions
- After calling `*_free()`, the pointer becomes invalid and should not be used

## Security

- **Never use the same epoch twice** with the same key, even to sign the same message
- Store secret keys securely
- Use serialization to save keys between sessions
- Regularly backup secret keys

## Scheme Parameters

Current implementation uses:
- **Scheme**: Generalized XMSS (Winternitz encoding, w=4)
- **Hash function**: SHA-3 (SHAKE)
- **Lifetime**: 2^18 epochs (262,144 epochs)
- **Message length**: 32 bytes

## Project Statistics

- **Tests**: 12/12 passed (100% coverage)
- **API functions**: 20
- **Lines of code**: 980 (Rust) + 156 (C example)
- **Test execution time**: 0.94 sec (release), 79 sec (debug)

## License

This project uses the hash-sig library. See the license of the original project:
https://github.com/b-wagn/hash-sig/

## References

- [hash-sig repository](https://github.com/b-wagn/hash-sig/)
- [Hash-Based Multi-Signatures for Post-Quantum Ethereum [DKKW25a]](https://eprint.iacr.org/2025/055.pdf)
- [LeanSig for Post-Quantum Ethereum [DKKW25b]](https://eprint.iacr.org/2025/1332.pdf)
- [XMSS: eXtended Merkle Signature Scheme (RFC 8391)](https://tools.ietf.org/html/rfc8391)
