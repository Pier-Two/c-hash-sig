#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "include/pq-bindings-c-rust.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
}

int main() {
    printf("=== PQ Bindings C Rust Example ===\n\n");
    
    // 1. Generate key pair
    printf("1. Generating key pair...\n");
    struct PQSignatureSchemePublicKey *pk = NULL;
    struct PQSignatureSchemeSecretKey *sk = NULL;
    
    // Create key for 10000 epochs, starting from epoch 0
    enum PQSigningError result = pq_key_gen(0, 10000, &pk, &sk);
    if (result != Success) {
        char *error = pq_error_description(result);
        printf("❌ Key generation error: %s\n", error);
        pq_string_free(error);
        return 1;
    }
    printf("✓ Keys generated successfully!\n\n");
    
    // 2. Get key information
    printf("2. Key information:\n");
    
    struct PQRange activation = pq_get_activation_interval(sk);
    printf("   Activation interval: %lu - %lu\n", activation.start, activation.end);
    
    struct PQRange prepared = pq_get_prepared_interval(sk);
    printf("   Prepared interval: %lu - %lu\n", prepared.start, prepared.end);
    
    uint64_t lifetime = pq_get_lifetime();
    printf("   Maximum scheme lifetime: %lu epochs\n\n", lifetime);
    
    // 3. Prepare message (must be exactly 32 bytes)
    printf("3. Preparing message...\n");
    uint8_t message[32];
    const char* text = "Hello, Post-Quantum World!";
    memset(message, 0, 32);
    strncpy((char*)message, text, 32);
    print_hex("   Message", message, 32);
    printf("\n");
    
    // 4. Sign message
    printf("4. Signing message for epoch 100...\n");
    struct PQSignature *signature = NULL;
    uint64_t epoch = 100;
    
    result = pq_sign(sk, epoch, message, 32, &signature);
    if (result != Success) {
        char *error = pq_error_description(result);
        printf("❌ Signing error: %s\n", error);
        pq_string_free(error);
        pq_secret_key_free(sk);
        pq_public_key_free(pk);
        return 1;
    }
    printf("✓ Message signed successfully!\n\n");
    
    // 5. Verify valid signature
    printf("5. Verifying signature...\n");
    int verify_result = pq_verify(pk, epoch, message, 32, signature);
    if (verify_result == 1) {
        printf("✓ Signature is valid!\n\n");
    } else if (verify_result == 0) {
        printf("❌ Signature is invalid!\n\n");
    } else {
        printf("❌ Verification error (code: %d)\n\n", verify_result);
    }
    
    // 6. Verify with modified message (should fail)
    printf("6. Testing with modified message...\n");
    uint8_t wrong_message[32];
    memcpy(wrong_message, message, 32);
    wrong_message[0] = ~wrong_message[0]; // Invert first byte
    
    verify_result = pq_verify(pk, epoch, wrong_message, 32, signature);
    if (verify_result == 0) {
        printf("✓ Signature correctly identified as invalid for modified message!\n\n");
    } else {
        printf("❌ Unexpected verification result!\n\n");
    }
    
    // 7. Verify with wrong epoch (should fail)
    printf("7. Testing with wrong epoch...\n");
    verify_result = pq_verify(pk, epoch + 1, message, 32, signature);
    if (verify_result == 0) {
        printf("✓ Signature correctly identified as invalid for different epoch!\n\n");
    } else {
        printf("❌ Unexpected verification result!\n\n");
    }
    
    // 8. Demonstrate advance_preparation
    printf("8. Managing prepared interval...\n");
    printf("   Current prepared interval: %lu - %lu\n", prepared.start, prepared.end);
    
    pq_advance_preparation(sk);
    prepared = pq_get_prepared_interval(sk);
    printf("   After advance_preparation: %lu - %lu\n", prepared.start, prepared.end);
    printf("✓ Interval advanced successfully!\n\n");
    
    // 9. Serialization and deserialization
    printf("9. Testing serialization...\n");
    
    // Buffer for serialization (allocate enough space)
    uint8_t pk_buffer[100000];
    size_t pk_written = 0;
    
    result = pq_public_key_serialize(pk, pk_buffer, sizeof(pk_buffer), &pk_written);
    if (result == Success) {
        printf("   Public key serialized: %zu bytes\n", pk_written);
        
        // Deserialization
        struct PQSignatureSchemePublicKey *pk_restored = NULL;
        result = pq_public_key_deserialize(pk_buffer, pk_written, &pk_restored);
        if (result == Success) {
            printf("   Public key deserialized successfully!\n");
            
            // Verify restored key works
            verify_result = pq_verify(pk_restored, epoch, message, 32, signature);
            if (verify_result == 1) {
                printf("✓ Restored key works correctly!\n");
            }
            
            pq_public_key_free(pk_restored);
        }
    } else {
        char *error = pq_error_description(result);
        printf("❌ Serialization error: %s\n", error);
        pq_string_free(error);
    }
    printf("\n");
    
    // 10. Free resources
    printf("10. Freeing resources...\n");
    pq_signature_free(signature);
    pq_secret_key_free(sk);
    pq_public_key_free(pk);
    printf("✓ All resources freed!\n\n");
    
    printf("=== Example completed successfully! ===\n");
    return 0;
}
