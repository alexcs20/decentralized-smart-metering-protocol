#ifndef SMART_METER_H
#define SMART_METER_H

#include <stdint.h>
#include <gmp.h>
#include <pthread.h>
#include "crypto_utils.h"
#include "shamir_secret.h"
#include "config.h"

// Meter status
typedef enum {
    METER_ACTIVE,
    METER_INACTIVE,
    METER_SUSPECT,
    METER_MALICIOUS
} MeterStatus;

// Smart meter structure
typedef struct {
    uint8_t id;                      // Meter ID (1-20)
    uint64_t reading;                 // Current reading R_i,r
    mpz_t random_value;                // Random pi for Phase 1
    uint8_t commitment_hash[HASH_SIZE]; // Hash commitment Hi
    PedersenCommitment pedersen_comm;   // Phase 3 commitment
    
    // Security
    uint8_t public_key[32];            // Public key for authentication
    uint8_t private_key[32];            // Private key (kept secret)
    MeterStatus status;                 // Current status
    
    // Committee membership
    int is_committee_member;            // Is in current committee?
    uint8_t last_committee_round;       // Last round in committee
    
    // Received shares (for committee members)
    Share received_shares[NUM_SMART_METERS];
    int num_received_shares;
    
    // Statistics
    int times_selected;                  // Times selected as committee
    uint64_t total_reading;               // Total energy supplied
    double total_cost;                     // Total cost incurred
    
    // Threading
    pthread_t thread;
    pthread_mutex_t lock;
} SmartMeter;

// Initialize meter
void meter_init(SmartMeter *meter, uint8_t id);

// PHASE 1: Commit-reveal functions
void meter_generate_random(SmartMeter *meter, uint32_t round);
int meter_create_commitment(SmartMeter *meter, uint32_t round);
int meter_reveal_random(SmartMeter *meter, uint32_t round);

// PHASE 3: Reading commitment
int meter_create_reading_commitment(SmartMeter *meter, uint32_t round);

// PHASE 4: Share generation and distribution
int meter_generate_shares(SmartMeter *meter, uint8_t *committee,
                          uint32_t round, EncryptedShare *encrypted_shares);
int meter_send_shares(SmartMeter *meter, EncryptedShare *shares, int num_shares);
int meter_receive_share(SmartMeter *meter, EncryptedShare *share);
int meter_verify_share(SmartMeter *meter, EncryptedShare *share);

// PHASE 5: Aggregation (for committee members)
int meter_aggregate_shares(SmartMeter *meter, uint32_t round, mpz_t aggregated);

// Utility functions
void meter_generate_reading(SmartMeter *meter, uint32_t round);
void meter_print_info(SmartMeter *meter);
void meter_lock(SmartMeter *meter);
void meter_unlock(SmartMeter *meter);

// Cleanup
void meter_free(SmartMeter *meter);

#endif // SMART_METER_H
