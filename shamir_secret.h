#ifndef SHAMIR_SECRET_H
#define SHAMIR_SECRET_H

#include <stdint.h>
#include <gmp.h>
#include "config.h"

// Share structure
typedef struct {
    int x;              // Committee member ID (1-10)
    mpz_t value;        // Share value f(x)
} Share;

// Polynomial structure
typedef struct {
    mpz_t *coefficients; // Polynomial coefficients [0..degree]
    int degree;          // Degree of polynomial (THRESHOLD - 1)
} Polynomial;

// Encrypted share for secure transmission
typedef struct {
    uint8_t meter_id;           // Source meter
    uint8_t committee_member_id; // Target committee member
    uint32_t round;              // Round number
    int x;                       // x-coordinate (member ID)
    mpz_t encrypted_value;       // Encrypted share value
    uint8_t hmac[HASH_SIZE];     // Integrity check
} EncryptedShare;

// PHASE 4: Share generation functions
void create_polynomial(Polynomial *poly, uint64_t secret, int degree);
void evaluate_polynomial(mpz_t result, Polynomial *poly, int x);
void generate_shares(Share *shares, uint64_t secret, int num_shares, int threshold);
int verify_share(Share *share, Polynomial *poly);

// PHASE 4: Secure share transmission
int encrypt_share(EncryptedShare *encrypted, Share *share,
                  uint8_t meter_id, uint8_t committee_id, uint32_t round,
                  uint8_t *recipient_public_key);
int decrypt_share(Share *share, EncryptedShare *encrypted,
                  uint8_t *recipient_private_key);
void compute_share_hmac(uint8_t *hmac, EncryptedShare *share);
int verify_share_hmac(EncryptedShare *share);

// PHASE 6: Reconstruction functions
int reconstruct_secret(mpz_t result, Share *shares, int num_shares, int threshold);
int reconstruct_with_lagrange(mpz_t result, Share *shares, int num_shares);

// Utility functions
void polynomial_free(Polynomial *poly);
void share_free(Share *share);
void encrypted_share_free(EncryptedShare *share);

#endif // SHAMIR_SECRET_H
