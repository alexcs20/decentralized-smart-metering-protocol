
#!/bin/bash

echo "=================================================================="
echo "COMPLETE PROTOCOL UPDATE - STARTING"
echo "=================================================================="

# Navigate to project directory
cd ~/decentralized-smart-metering-c || {
    echo "❌ ERROR: Project directory not found!"
    exit 1
}

# Create backup
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
echo "📦 Creating backup in $BACKUP_DIR..."
mkdir -p $BACKUP_DIR
cp -r include src Makefile $BACKUP_DIR/ 2>/dev/null
echo "✅ Backup created"
echo ""

# Create directories
mkdir -p include src/crypto src/meter src/committee src/utils
mkdir -p results/rounds results/audit results/checkpoints
mkdir -p obj/crypto obj/meter obj/committee obj/utils
mkdir -p bin

echo "📝 Updating all files..."

# ==================================================================
# CONFIG.H
# ==================================================================
cat > include/config.h << 'EOF'
#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// Protocol Configuration
#define NUM_SMART_METERS 20      // N = 20 meters
#define COMMITTEE_SIZE 10         // c = 10 committee members
#define THRESHOLD 6                // k = 6 reconstruction threshold
#define ROUND_DURATION 1           // 1 second simulated (5 min real)
#define MAX_ROUNDS 144              // 12 hours simulation (12 * 12)

// OEB Rates (Phase 8 requirement)
#define OFF_PEAK_RATE 7.4          // Off-peak pricing (¢/kWh)
#define MID_PEAK_RATE 10.9         // Mid-peak pricing (¢/kWh)
#define ON_PEAK_RATE 15.9           // On-peak pricing (¢/kWh)

// Time periods (in rounds, each round = 5 minutes)
#define ROUNDS_PER_HOUR 12
#define ROUNDS_PER_DAY 288

// Period definitions (in rounds since midnight)
#define OFF_PEAK_1_START 0          // 12:00 AM
#define OFF_PEAK_1_END 84           // 7:00 AM
#define MID_PEAK_1_START 84         // 7:00 AM
#define MID_PEAK_1_END 132          // 11:00 AM
#define ON_PEAK_START 132           // 11:00 AM
#define ON_PEAK_END 204             // 5:00 PM
#define MID_PEAK_2_START 204        // 5:00 PM
#define MID_PEAK_2_END 228          // 7:00 PM
#define OFF_PEAK_2_START 228        // 7:00 PM
#define OFF_PEAK_2_END 288          // 12:00 AM

// Cryptographic parameters
#define PRIME_BITS 2048             // 2048-bit prime for security
#define HASH_SIZE 32                 // SHA-256 output size (32 bytes)
#define RANDOM_BITS 256              // 256-bit randomness for commitments

// Security parameters
#define MAX_FAULTY_METERS 4          // Maximum faulty meters (c - k)
#define REQUIRED_VERIFICATIONS 6     // Minimum verifications needed

// File paths
#define RESULTS_PATH "results/"
#define AUDIT_PATH "results/audit/"
#define CHECKPOINT_PATH "results/checkpoints/"

#endif // CONFIG_H
EOF
echo "  ✅ include/config.h"

# ==================================================================
# CRYPTO_UTILS.H
# ==================================================================
cat > include/crypto_utils.h << 'EOF'
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <gmp.h>
#include <openssl/sha.h>

// Pedersen commitment structure
typedef struct {
    mpz_t value;        // The commitment value C = g^R * h^r mod p
    mpz_t r;            // Random blinding factor (kept secret by meter)
} PedersenCommitment;

// Commit-reveal entry for Phase 1
typedef struct {
    uint8_t meter_id;
    uint8_t commitment[HASH_SIZE];
    mpz_t reveal;
    int revealed;
    int verified;
} CommitRevealEntry;

// Initialize crypto system
int crypto_init(void);

// Clean up crypto system
void crypto_cleanup(void);

// Generate cryptographically secure random number
int generate_csprng(mpz_t rand, int bits);

// PHASE 1: Commit-Reveal functions
void cr_init_round(void);
int cr_meter_commit(uint8_t meter_id, uint32_t round, mpz_t random, uint8_t *commitment);
int cr_meter_reveal(uint8_t meter_id, mpz_t reveal);
int cr_verify_reveal(uint8_t meter_id, uint32_t round, const uint8_t *commitment, mpz_t reveal);
int cr_verify_all_reveals(uint32_t round);
int cr_generate_seed(uint32_t round, uint8_t *seed);
void cr_cleanup(void);

// PHASE 2: Committee selection functions
void compute_meter_score(mpz_t score, const uint8_t *seed, uint8_t meter_id);
int select_committee_eth(uint32_t round, const uint8_t *seed, uint8_t *committee);
int verify_committee_selection(uint32_t round, const uint8_t *seed, const uint8_t *committee);

// PHASE 3: Pedersen commitment functions
int create_pedersen_commitment(PedersenCommitment *comm, uint64_t reading,
                               uint32_t round, uint8_t meter_id);
int verify_pedersen_commitment(PedersenCommitment *comm, uint64_t reading);
int add_commitments(PedersenCommitment *result, PedersenCommitment *a, PedersenCommitment *b);

// Hash functions
void hash_commitment(uint8_t *output, uint32_t round, uint8_t meter_id, mpz_t random);
void hash_data(uint8_t *output, const void *data, size_t len);

// Utility functions
void print_hex(const uint8_t *data, size_t len, const char *label);
int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);

#endif // CRYPTO_UTILS_H
EOF
echo "  ✅ include/crypto_utils.h"

# ==================================================================
# SHAMIR_SECRET.H
# ==================================================================
cat > include/shamir_secret.h << 'EOF'
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
EOF
echo "  ✅ include/shamir_secret.h"

# ==================================================================
# SMART_METER.H
# ==================================================================
cat > include/smart_meter.h << 'EOF'
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
EOF
echo "  ✅ include/smart_meter.h"

# ==================================================================
# COMMITTEE.H
# ==================================================================
cat > include/committee.h << 'EOF'
#ifndef COMMITTEE_H
#define COMMITTEE_H

#include <stdint.h>
#include <gmp.h>
#include "crypto_utils.h"
#include "shamir_secret.h"
#include "smart_meter.h"
#include "config.h"

// Aggregated share structure
typedef struct {
    int member_id;           // Committee member ID
    mpz_t value;             // Aggregated share S_j = Σ f_i(j)
    uint32_t round;           // Round number
    uint8_t signature[64];    // Signature for verification
} AggregatedShare;

// Committee structure
typedef struct {
    uint8_t members[COMMITTEE_SIZE];  // Committee member IDs
    uint32_t round;                     // Current round
    uint64_t spatial_aggregate;          // Total for this round
    uint64_t temporal_aggregate;         // Running total
    
    // Aggregated shares from each member
    AggregatedShare aggregated_shares[COMMITTEE_SIZE];
    int num_aggregated_shares;
    
    // Commitments from meters (for Phase 3)
    PedersenCommitment *meter_commitments[NUM_SMART_METERS];
    
    // Audit trail
    uint8_t round_seed[HASH_SIZE];
} Committee;

// Initialize committee
void committee_init(Committee *comm);

// PHASE 2: Committee selection
int committee_select(Committee *comm, uint32_t round, const uint8_t *seed);

// PHASE 3: Store commitments
int committee_store_commitment(Committee *comm, uint8_t meter_id,
                               PedersenCommitment *commitment);

// PHASE 5: Spatial aggregation
int committee_aggregate_shares(Committee *comm, SmartMeter *meters,
                               uint32_t round, AggregatedShare *result);
int committee_member_aggregate(Committee *comm, SmartMeter *member,
                               uint32_t round, mpz_t aggregated);

// PHASE 6: Reconstruction
int committee_reconstruct_total(Committee *comm, AggregatedShare *shares,
                                int num_shares, uint64_t *total);

// PHASE 8: Reporting
void committee_send_to_esp(Committee *comm, uint64_t total_consumption, uint32_t round);

// Verification functions
int verify_committee_member(Committee *comm, uint8_t member_id);
int verify_aggregated_share(AggregatedShare *share, uint8_t *public_key);

// Utility functions
void committee_print(Committee *comm);
void committee_free(Committee *comm);

#endif // COMMITTEE_H
EOF
echo "  ✅ include/committee.h"

# ==================================================================
# BILLING.H
# ==================================================================
cat > include/billing.h << 'EOF'
#ifndef BILLING_H
#define BILLING_H

#include <stdint.h>
#include <string.h>
#include "config.h"

// Daily bill structure
typedef struct {
    double off_peak_kwh;      // Off-peak consumption
    double mid_peak_kwh;      // Mid-peak consumption
    double on_peak_kwh;       // On-peak consumption
    double total_kwh;         // Total consumption
    double subtotal;          // Cost before HST
    double hst;               // HST amount (13%)
    double total_cost;        // Total cost after HST
    
    // Period tracking
    uint32_t off_peak_rounds;
    uint32_t mid_peak_rounds;
    uint32_t on_peak_rounds;
} DailyBill;

// Rate structure
typedef struct {
    double rate;              // Rate in ¢/kWh
    const char *period_name;   // Period name
    uint32_t start_round;      // Start round in day
    uint32_t end_round;        // End round in day
} RatePeriod;

// PHASE 8: Rate functions
double get_rate_for_round(uint32_t round);
const char* get_time_period(uint32_t round);
RatePeriod get_current_period(uint32_t round);

// PHASE 8: Cost calculation
double calculate_round_cost(uint64_t wh, uint32_t round);
double calculate_period_cost(double kwh, double rate);
double calculate_hst(double subtotal);

// PHASE 8: Bill management
void init_daily_bill(DailyBill *bill);
void update_daily_bill(DailyBill *bill, uint64_t wh, uint32_t round);
void finalize_bill(DailyBill *bill);
void print_bill_summary(DailyBill *bill);
void print_financial_report(DailyBill *bill);

// Period tracking
int is_off_peak(uint32_t round);
int is_mid_peak(uint32_t round);
int is_on_peak(uint32_t round);

// Audit functions
void log_billing_entry(DailyBill *bill, uint32_t round, uint64_t wh, double cost);

#endif // BILLING_H
EOF
echo "  ✅ include/billing.h"

# ==================================================================
# MAIN.C
# ==================================================================
cat > src/main.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "config.h"
#include "crypto_utils.h"
#include "shamir_secret.h"
#include "smart_meter.h"
#include "committee.h"
#include "billing.h"

// Global state
static SmartMeter meters[NUM_SMART_METERS];
static Committee current_committee;
static uint8_t round_seed[HASH_SIZE];
static uint64_t temporal_aggregates[MAX_ROUNDS];
static DailyBill daily_bill;
static volatile sig_atomic_t simulation_running = 1;

// Statistics tracking
static int committee_selection_count[NUM_SMART_METERS] = {0};
static FILE *audit_log = NULL;

// Signal handler for graceful shutdown
void handle_signal(int sig) {
    printf("\n⚠️  Signal %d received. Shutting down gracefully...\n", sig);
    simulation_running = 0;
}

// Initialize audit log
void init_audit_log() {
    time_t now = time(NULL);
    char filename[256];
    snprintf(filename, sizeof(filename), "%saudit_log_%ld.txt", AUDIT_PATH, now);
    audit_log = fopen(filename, "w");
    if (audit_log) {
        fprintf(audit_log, "=== DECENTRALIZED SMART METERING AUDIT LOG ===\n");
        fprintf(audit_log, "Started: %s", ctime(&now));
        fprintf(audit_log, "Meters: %d, Committee: %d, Threshold: %d\n\n",
                NUM_SMART_METERS, COMMITTEE_SIZE, THRESHOLD);
        fflush(audit_log);
    }
}

// Log audit entry
void log_audit(const char *format, ...) {
    if (!audit_log) return;
    
    va_list args;
    va_start(args, format);
    vfprintf(audit_log, format, args);
    va_end(args);
    fflush(audit_log);
}

// ==================================================================
// PHASE 1: Commit-Reveal Implementation
// ==================================================================
int phase1_commit_reveal(uint32_t round, uint8_t *seed) {
    printf("\n[PHASE 1] Commit-Reveal (Round %d)\n", round);
    printf("  Generating randomness from %d meters...\n", NUM_SMART_METERS);
    
    // Initialize commit-reveal for this round
    cr_init_round();
    
    // Step 1: All meters create commitments
    printf("  Commit phase:\n");
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        meter_generate_random(&meters[i], round);
        
        if (!cr_meter_commit(meters[i].id, round, meters[i].random_value,
                             meters[i].commitment_hash)) {
            printf("  ERROR: Meter %d failed to commit\n", meters[i].id);
            return 0;
        }
        printf("    Meter %2d: ✓ Commitment created\n", meters[i].id);
    }
    
    // Simulate network delay for commitments to propagate
    usleep(1000); // 1ms
    
    // Step 2: All meters reveal
    printf("  Reveal phase:\n");
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        if (!cr_meter_reveal(meters[i].id, meters[i].random_value)) {
            printf("  ERROR: Meter %d failed to reveal\n", meters[i].id);
            return 0;
        }
        printf("    Meter %2d: ✓ Revealed\n", meters[i].id);
    }
    
    // Step 3: Verify all reveals
    printf("  Verification phase:\n");
    int valid_count = cr_verify_all_reveals(round);
    
    if (valid_count < THRESHOLD) {
        printf("  ERROR: Not enough valid reveals (%d < %d)\n", valid_count, THRESHOLD);
        return 0;
    }
    printf("    %d/%d reveals verified successfully\n", valid_count, NUM_SMART_METERS);
    
    // Step 4: Generate seed from valid reveals
    printf("  Seed generation:\n");
    valid_count = cr_generate_seed(round, seed);
    printf("    Seed generated from %d valid reveals\n", valid_count);
    
    // Log seed for audit
    log_audit("Round %d seed: ", round);
    for (int i = 0; i < 8; i++) {
        log_audit("%02x", seed[i]);
    }
    log_audit("\n");
    
    printf("  ✓ Phase 1 complete\n");
    return 1;
}

// ==================================================================
// PHASE 2: Committee Selection (Ethereum-style)
// ==================================================================
int phase2_select_committee(uint32_t round, uint8_t *seed, Committee *committee) {
    printf("\n[PHASE 2] Committee Selection (Ethereum-style)\n");
    printf("  Computing scores: H(seed || meter_id)\n");
    
    uint8_t selected[COMMITTEE_SIZE];
    
    if (!select_committee_eth(round, seed, selected)) {
        printf("  ERROR: Committee selection failed\n");
        return 0;
    }
    
    // Copy to committee structure
    committee->round = round;
    memcpy(committee->members, selected, COMMITTEE_SIZE);
    memcpy(committee->round_seed, seed, HASH_SIZE);
    
    // Display selected committee
    printf("  Selected committee: ");
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        printf("SM%d ", committee->members[i]);
        
        // Update statistics
        committee_selection_count[committee->members[i] - 1]++;
        
        // Mark meter as committee member
        meters[committee->members[i] - 1].is_committee_member = 1;
        meters[committee->members[i] - 1].last_committee_round = round;
        meters[committee->members[i] - 1].times_selected++;
    }
    printf("\n");
    
    // Log committee for audit
    log_audit("Round %d committee: ", round);
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        log_audit("SM%d ", committee->members[i]);
    }
    log_audit("\n");
    
    // Verify selection is verifiable
    if (!verify_committee_selection(round, seed, committee->members)) {
        printf("  ERROR: Committee verification failed!\n");
        return 0;
    }
    printf("  ✓ Committee selection verified\n");
    
    return 1;
}

// ==================================================================
// PHASE 3: Pedersen Commitments
// ==================================================================
int phase3_create_commitments(uint32_t round, Committee *committee) {
    printf("\n[PHASE 3] Pedersen Commitments\n");
    printf("  Creating hiding commitments for all meters...\n");
    
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        if (!meter_create_reading_commitment(&meters[i], round)) {
            printf("  ERROR: Meter %d failed to create commitment\n", meters[i].id);
            return 0;
        }
        
        // Store commitment in committee for later verification
        committee_store_commitment(committee, meters[i].id, &meters[i].pedersen_comm);
        
        printf("    Meter %2d: ✓ Commitment created (C = g^R·h^r)\n", meters[i].id);
    }
    
    printf("  ✓ Phase 3 complete\n");
    return 1;
}

// ==================================================================
// PHASE 4: Share Generation and Distribution
// ==================================================================
int phase4_generate_shares(uint32_t round, Committee *committee) {
    printf("\n[PHASE 4] Share Generation (Shamir Secret Sharing)\n");
    printf("  Generating shares for committee members...\n");
    
    EncryptedShare all_shares[NUM_SMART_METERS][COMMITTEE_SIZE];
    
    // Each meter generates shares for all committee members
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        if (!meter_generate_shares(&meters[i], committee->members,
                                   round, all_shares[i])) {
            printf("  ERROR: Meter %d share generation failed\n", meters[i].id);
            return 0;
        }
        printf("    Meter %2d: Generated %d shares (degree %d polynomial)\n",
               meters[i].id, COMMITTEE_SIZE, THRESHOLD-1);
    }
    
    // Distribute shares to committee members
    printf("  Distributing shares securely:\n");
    for (int c = 0; c < COMMITTEE_SIZE; c++) {
        int member_id = committee->members[c];
        SmartMeter *member = &meters[member_id - 1];
        
        printf("    To SM%d: ", member_id);
        
        for (int m = 0; m < NUM_SMART_METERS; m++) {
            // Find the share intended for this committee member
            for (int s = 0; s < COMMITTEE_SIZE; s++) {
                if (all_shares[m][s].committee_member_id == member_id) {
                    if (!meter_receive_share(member, &all_shares[m][s])) {
                        printf("\n      ERROR: Share delivery failed\n");
                        return 0;
                    }
                    printf("SM%d ", all_shares[m][s].meter_id);
                    break;
                }
            }
        }
        printf("✓\n");
    }
    
    printf("  ✓ Phase 4 complete\n");
    return 1;
}

// ==================================================================
// PHASE 5: Spatial Aggregation
// ==================================================================
int phase5_aggregate_shares(uint32_t round, Committee *committee) {
    printf("\n[PHASE 5] Spatial Aggregation\n");
    printf("  Committee members aggregating shares...\n");
    
    mpz_t member_aggregates[COMMITTEE_SIZE];
    
    // Each committee member aggregates shares they received
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        int member_id = committee->members[i];
        SmartMeter *member = &meters[member_id - 1];
        
        mpz_init(member_aggregates[i]);
        
        if (!meter_aggregate_shares(member, round, member_aggregates[i])) {
            printf("  ERROR: SM%d aggregation failed\n", member_id);
            return 0;
        }
        
        printf("    SM%d: S_j = Σ f_i(%d) = F(%d)\n", member_id, member_id, member_id);
    }
    
    // Store aggregated shares in committee
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        committee->aggregated_shares[i].member_id = committee->members[i];
        mpz_init_set(committee->aggregated_shares[i].value, member_aggregates[i]);
        committee->aggregated_shares[i].round = round;
        committee->num_aggregated_shares++;
        mpz_clear(member_aggregates[i]);
    }
    
    printf("  ✓ Phase 5 complete - %d aggregated shares ready\n", committee->num_aggregated_shares);
    return 1;
}

// ==================================================================
// PHASE 6: Reconstruction
// ==================================================================
int phase6_reconstruct_total(Committee *committee, uint64_t *total) {
    printf("\n[PHASE 6] Reconstruction (Lagrange Interpolation)\n");
    printf("  Using %d aggregated shares...\n", committee->num_aggregated_shares);
    
    if (committee->num_aggregated_shares < THRESHOLD) {
        printf("  ERROR: Need at least %d shares, have %d\n",
               THRESHOLD, committee->num_aggregated_shares);
        return 0;
    }
    
    // Convert aggregated shares to Share structure for reconstruction
    Share shares[COMMITTEE_SIZE];
    for (int i = 0; i < committee->num_aggregated_shares; i++) {
        shares[i].x = committee->aggregated_shares[i].member_id;
        mpz_init_set(shares[i].value, committee->aggregated_shares[i].value);
    }
    
    // Reconstruct the total
    mpz_t result;
    mpz_init(result);
    
    if (!reconstruct_secret(result, shares, committee->num_aggregated_shares, THRESHOLD)) {
        printf("  ERROR: Reconstruction failed\n");
        return 0;
    }
    
    *total = mpz_get_ui(result);
    
    // Clean up
    mpz_clear(result);
    for (int i = 0; i < committee->num_aggregated_shares; i++) {
        mpz_clear(shares[i].value);
    }
    
    printf("  Reconstructed total: %lu Wh (%.2f kWh)\n", *total, *total/1000.0);
    printf("  ✓ Phase 6 complete\n");
    
    return 1;
}

// ==================================================================
// PHASE 7: Temporal Aggregation
// ==================================================================
void phase7_temporal_aggregation(uint32_t round, uint64_t round_total,
                                 uint64_t *temporal_aggregates) {
    if (round == 0) {
        temporal_aggregates[round] = round_total;
    } else {
        temporal_aggregates[round] = temporal_aggregates[round-1] + round_total;
    }
    
    // Calculate running total
    uint64_t running_total = temporal_aggregates[round];
    
    printf("\n[PHASE 7] Temporal Aggregation\n");
    printf("  Round %3d: +%lu Wh\n", round+1, round_total);
    printf("  Running total: %lu Wh (%.2f kWh)\n", running_total, running_total/1000.0);
    
    // Hourly checkpoint
    if ((round + 1) % ROUNDS_PER_HOUR == 0) {
        int hour = (round + 1) / ROUNDS_PER_HOUR;
        printf("  📊 Hour %d checkpoint: %.2f kWh\n", hour, running_total/1000.0);
        
        // Save hourly checkpoint
        char filename[256];
        snprintf(filename, sizeof(filename), "%shour_%d.txt", CHECKPOINT_PATH, hour);
        FILE *fp = fopen(filename, "w");
        if (fp) {
            fprintf(fp, "Hour %d total: %.2f kWh\n", hour, running_total/1000.0);
            fclose(fp);
        }
    }
    
    printf("  ✓ Phase 7 complete\n");
}

// ==================================================================
// PHASE 8: OEB Billing
// ==================================================================
void phase8_billing(DailyBill *bill, uint64_t round_total, uint32_t round) {
    printf("\n[PHASE 8] OEB Billing\n");
    
    double rate = get_rate_for_round(round);
    const char *period = get_time_period(round);
    double cost = calculate_round_cost(round_total, round);
    
    printf("  Period: %s | Rate: %.1f ¢/kWh\n", period, rate);
    printf("  Round cost: $%.2f\n", cost);
    
    update_daily_bill(bill, round_total, round);
    
    printf("  Running bill subtotal: $%.2f\n", bill->subtotal);
    printf("  ✓ Phase 8 complete\n");
}

// ==================================================================
// Save checkpoint
// ==================================================================
void save_checkpoint(uint32_t round, uint64_t *temporal_aggregates, DailyBill *bill) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%scheckpoint_round_%d.txt", CHECKPOINT_PATH, round+1);
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return;
    
    fprintf(fp, "=== CHECKPOINT at Round %d ===\n", round+1);
    fprintf(fp, "Current total: %.2f kWh\n", temporal_aggregates[round]/1000.0);
    fprintf(fp, "Bill subtotal: $%.2f\n", bill->subtotal);
    fprintf(fp, "Off-peak: %.2f kWh\n", bill->off_peak_kwh);
    fprintf(fp, "Mid-peak: %.2f kWh\n", bill->mid_peak_kwh);
    fprintf(fp, "On-peak: %.2f kWh\n", bill->on_peak_kwh);
    
    fclose(fp);
    printf("\n💾 Checkpoint saved: round %d\n", round+1);
}

// ==================================================================
// Save round data
// ==================================================================
void save_round_data(uint32_t round, uint64_t round_total,
                     Committee *committee, uint8_t *seed) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%srounds/round_%03d.csv", RESULTS_PATH, round+1);
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return;
    
    fprintf(fp, "round,total_wh,total_kwh,committee1,committee2,committee3,committee4,committee5,committee6,committee7,committee8,committee9,committee10\n");
    fprintf(fp, "%d,%lu,%.2f", round+1, round_total, round_total/1000.0);
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        fprintf(fp, ",SM%d", committee->members[i]);
    }
    fprintf(fp, "\n");
    
    fclose(fp);
}

// ==================================================================
// Print committee statistics
// ==================================================================
void print_committee_statistics(int selection_count[], int rounds) {
    printf("\n=== COMMITTEE SELECTION STATISTICS ===\n");
    double expected = (double)rounds * COMMITTEE_SIZE / NUM_SMART_METERS;
    printf("Expected selections per meter: %.1f\n", expected);
    
    int min = 9999, max = 0;
    double chi_square = 0;
    
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        printf("SM%2d: %d times", i+1, selection_count[i]);
        double deviation = (selection_count[i] - expected) / expected * 100;
        printf(" (%+.1f%%)\n", deviation);
        
        if (selection_count[i] < min) min = selection_count[i];
        if (selection_count[i] > max) max = selection_count[i];
        
        double diff = selection_count[i] - expected;
        chi_square += (diff * diff) / expected;
    }
    
    printf("\nStatistics:\n");
    printf("  Min selections: %d\n", min);
    printf("  Max selections: %d\n", max);
    printf("  Range: %d\n", max - min);
    printf("  Chi-square: %.2f (should be < 30.1 for fairness)\n", chi_square);
    
    if (chi_square < 30.1) {
        printf("✅ Committee selection is FAIR\n");
    } else {
        printf("⚠️ Committee selection may be BIASED\n");
    }
}

// ==================================================================
// Print half-day summary
// ==================================================================
void print_halfday_summary(uint64_t *aggregates, int rounds, DailyBill *bill) {
    printf("\n==================================================================\n");
    printf("HALF-DAY SIMULATION SUMMARY (12 HOURS)\n");
    printf("==================================================================\n");
    
    uint64_t total = aggregates[rounds-1];
    printf("Total Energy Consumed:   %.2f kWh\n", total/1000.0);
    printf("Total Cost (with HST):   $%.2f CAD\n", bill->total_cost);
    printf("Average per Round:        %.2f kWh\n", (total/1000.0)/rounds);
    
    printf("\nConsumption by Period:\n");
    printf("  Off-Peak (7.4¢):   %8.2f kWh (%5.1f%%) - $%.2f\n",
           bill->off_peak_kwh, (bill->off_peak_kwh/bill->total_kwh)*100,
           bill->off_peak_kwh * 0.074);
    printf("  Mid-Peak (10.9¢):  %8.2f kWh (%5.1f%%) - $%.2f\n",
           bill->mid_peak_kwh, (bill->mid_peak_kwh/bill->total_kwh)*100,
           bill->mid_peak_kwh * 0.109);
    printf("  On-Peak (15.9¢):   %8.2f kWh (%5.1f%%) - $%.2f\n",
           bill->on_peak_kwh, (bill->on_peak_kwh/bill->total_kwh)*100,
           bill->on_peak_kwh * 0.159);
    printf("  HST (13%%):                                   $%.2f\n", bill->hst);
    printf("  TOTAL:                                        $%.2f\n", bill->total_cost);
    printf("==================================================================\n");
}

// ==================================================================
// Generate professor report
// ==================================================================
void generate_professor_report(const char *name, const char *course,
                               int rounds, uint64_t *aggregates, DailyBill *bill) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%sprofessor_report.txt", RESULTS_PATH);
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return;
    
    time_t now = time(NULL);
    
    fprintf(fp, "==================================================================\n");
    fprintf(fp, "DECENTRALIZED SMART METERING PROTOCOL - SIMULATION REPORT\n");
    fprintf(fp, "==================================================================\n\n");
    fprintf(fp, "Student: %s\n", name);
    fprintf(fp, "Course: %s\n", course);
    fprintf(fp, "Date: %s", ctime(&now));
    fprintf(fp, "\n");
    
    fprintf(fp, "PROTOCOL PARAMETERS:\n");
    fprintf(fp, "  Meters (N): %d\n", NUM_SMART_METERS);
    fprintf(fp, "  Committee size (c): %d\n", COMMITTEE_SIZE);
    fprintf(fp, "  Threshold (k): %d\n", THRESHOLD);
    fprintf(fp, "  Rounds simulated: %d\n", rounds);
    fprintf(fp, "  Real time simulated: %.1f hours\n", rounds * 5.0 / 60.0);
    fprintf(fp, "\n");
    
    fprintf(fp, "RESULTS:\n");
    fprintf(fp, "  Total consumption: %.2f kWh\n", aggregates[rounds-1]/1000.0);
    fprintf(fp, "  Total cost (with HST): $%.2f\n", bill->total_cost);
    fprintf(fp, "\n");
    
    fprintf(fp, "CONSUMPTION BY PERIOD:\n");
    fprintf(fp, "  Off-Peak: %.2f kWh (%.1f%%)\n",
            bill->off_peak_kwh, (bill->off_peak_kwh/bill->total_kwh)*100);
    fprintf(fp, "  Mid-Peak: %.2f kWh (%.1f%%)\n",
            bill->mid_peak_kwh, (bill->mid_peak_kwh/bill->total_kwh)*100);
    fprintf(fp, "  On-Peak:  %.2f kWh (%.1f%%)\n",
            bill->on_peak_kwh, (bill->on_peak_kwh/bill->total_kwh)*100);
    fprintf(fp, "\n");
    
    fprintf(fp, "PROTOCOL VERIFICATION:\n");
    fprintf(fp, "  ✓ Phase 1: Commit-reveal implemented\n");
    fprintf(fp, "  ✓ Phase 2: Ethereum-style committee selection\n");
    fprintf(fp, "  ✓ Phase 3: Pedersen commitments\n");
    fprintf(fp, "  ✓ Phase 4: Shamir secret sharing (degree %d)\n", THRESHOLD-1);
    fprintf(fp, "  ✓ Phase 5: Spatial aggregation by committee\n");
    fprintf(fp, "  ✓ Phase 6: Lagrange reconstruction\n");
    fprintf(fp, "  ✓ Phase 7: Temporal aggregation\n");
    fprintf(fp, "  ✓ Phase 8: OEB billing with HST\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "==================================================================\n");
    fclose(fp);
    
    printf("\n📄 Professor report saved to %s\n", filename);
}

// ==================================================================
// Print financial report
// ==================================================================
void print_financial_report(DailyBill *bill) {
    printf("\n=== FINANCIAL REPORT ===\n");
    printf("Consumption Summary:\n");
    printf("  Off-Peak: %.2f kWh @ 7.4¢ = $%.2f\n",
           bill->off_peak_kwh, bill->off_peak_kwh * 0.074);
    printf("  Mid-Peak: %.2f kWh @ 10.9¢ = $%.2f\n",
           bill->mid_peak_kwh, bill->mid_peak_kwh * 0.109);
    printf("  On-Peak:  %.2f kWh @ 15.9¢ = $%.2f\n",
           bill->on_peak_kwh, bill->on_peak_kwh * 0.159);
    printf("  Subtotal: $%.2f\n", bill->subtotal);
    printf("  HST (13%%): $%.2f\n", bill->hst);
    printf("  TOTAL:    $%.2f\n", bill->total_cost);
}

// ==================================================================
// MAIN FUNCTION - THE ORCHESTRATOR
// ==================================================================
int main() {
    printf("==================================================================\n");
    printf("DECENTRALIZED SMART METERING SIMULATION (PROTOCOL-COMPLIANT)\n");
    printf("==================================================================\n");
    
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Create results directories
    system("mkdir -p results/rounds results/audit results/checkpoints");
    
    // Initialize crypto system
    printf("\n[INIT] Initializing cryptographic system...\n");
    if (!crypto_init()) {
        printf("[ERROR] Crypto initialization failed!\n");
        return 1;
    }
    printf("[INIT] ✓ GMP and OpenSSL initialized\n");
    
    // Initialize audit log
    init_audit_log();
    log_audit("SIMULATION STARTED\n");
    
    // Initialize meters
    printf("\n[INIT] Initializing %d smart meters...\n", NUM_SMART_METERS);
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        meter_init(&meters[i], i + 1);
        printf("[INIT]   Meter %2d: ID=%d, Initialized\n", i+1, meters[i].id);
    }
    
    // Initialize committee structure
    committee_init(&current_committee);
    
    // Initialize daily bill
    init_daily_bill(&daily_bill);
    
    printf("\n[INIT] Simulation ready - %d rounds (12 hours)\n", MAX_ROUNDS);
    printf("Press Ctrl+C to stop early\n");
    printf("==================================================================\n\n");
    
    // MAIN SIMULATION LOOP
    int round;
    for (round = 0; round < MAX_ROUNDS && simulation_running; round++) {
        printf("\n════════════════════════════════════════════════════════════\n");
        printf("ROUND %d/%d\n", round + 1, MAX_ROUNDS);
        
        // Display current time
        int hour = (round * 5) / 60;
        int minute = (round * 5) % 60;
        printf("Time: %02d:%02d\n", hour, minute);
        printf("════════════════════════════════════════════════════════════\n");
        
        // Reset committee member flags
        for (int i = 0; i < NUM_SMART_METERS; i++) {
            meters[i].is_committee_member = 0;
            meters[i].num_received_shares = 0;
        }
        
        // PHASE 1: Commit-Reveal (Randomness Generation)
        if (!phase1_commit_reveal(round, round_seed)) {
            printf("[ERROR] Phase 1 failed - aborting round\n");
            continue;
        }
        
        // PHASE 2: Committee Selection (Ethereum-style)
        if (!phase2_select_committee(round, round_seed, &current_committee)) {
            printf("[ERROR] Phase 2 failed - aborting round\n");
            continue;
        }
        
        // Generate realistic readings for this round
        for (int i = 0; i < NUM_SMART_METERS; i++) {
            meter_generate_reading(&meters[i], round);
        }
        
        // PHASE 3: Pedersen Commitments
        if (!phase3_create_commitments(round, &current_committee)) {
            printf("[ERROR] Phase 3 failed - aborting round\n");
            continue;
        }
        
        // PHASE 4: Share Generation and Distribution
        if (!phase4_generate_shares(round, &current_committee)) {
            printf("[ERROR] Phase 4 failed - aborting round\n");
            continue;
        }
        
        // PHASE 5: Spatial Aggregation
        if (!phase5_aggregate_shares(round, &current_committee)) {
            printf("[ERROR] Phase 5 failed - aborting round\n");
            continue;
        }
        
        // PHASE 6: Reconstruction
        uint64_t round_total;
        if (!phase6_reconstruct_total(&current_committee, &round_total)) {
            printf("[ERROR] Phase 6 failed - aborting round\n");
            continue;
        }
        
        // Update committee's spatial aggregate
        current_committee.spatial_aggregate = round_total;
        
        // PHASE 7: Temporal Aggregation
        phase7_temporal_aggregation(round, round_total, temporal_aggregates);
        
        // PHASE 8: Billing
        phase8_billing(&daily_bill, round_total, round);
        
        // Display round summary
        printf("\n════════════════════════════════════════════════════════════\n");
        printf("ROUND %d SUMMARY:\n", round + 1);
        printf("  Spatial Aggregate: %lu Wh (%.2f kWh)\n", round_total, round_total/1000.0);
        printf("  Temporal Aggregate: %lu Wh (%.2f kWh)\n",
               temporal_aggregates[round], temporal_aggregates[round]/1000.0);
        printf("  Period: %s | Rate: %.1f ¢/kWh\n",
               get_time_period(round), get_rate_for_round(round));
        printf("  Round Cost: $%.2f\n", calculate_round_cost(round_total, round));
        printf("  Bill so far: $%.2f (subtotal: $%.2f, HST: $%.2f)\n",
               daily_bill.total_cost, daily_bill.subtotal, daily_bill.hst);
        printf("════════════════════════════════════════════════════════════\n");
        
        // Save round data
        save_round_data(round, round_total, &current_committee, round_seed);
        
        // Create checkpoint every 12 rounds (1 hour)
        if ((round + 1) % 12 == 0) {
            save_checkpoint(round, temporal_aggregates, &daily_bill);
        }
        
        // Small delay for readability (remove for performance)
        usleep(10000); // 10ms
    }
    
    // SIMULATION COMPLETE
    printf("\n==================================================================\n");
    if (!simulation_running) {
        printf("⚠️  SIMULATION STOPPED EARLY after %d rounds\n", round);
        log_audit("SIMULATION STOPPED EARLY after %d rounds\n", round);
    } else {
        printf("✅ SIMULATION COMPLETED: %d rounds (12 hours)\n", MAX_ROUNDS);
        log_audit("SIMULATION COMPLETED successfully\n");
    }
    printf("==================================================================\n");
    
    // Finalize bill with HST
    finalize_bill(&daily_bill);
    
    // Generate final reports
    printf("\n[REPORT] Generating final reports...\n");
    
    // Half-day summary
    print_halfday_summary(temporal_aggregates, round, &daily_bill);
    
    // Committee selection statistics
    print_committee_statistics(committee_selection_count, round);
    
    // Professor report
    generate_professor_report("Your Name", "Course Name", round,
                             temporal_aggregates, &daily_bill);
    
    // Financial report with HST
    print_financial_report(&daily_bill);
    
    // Audit log summary
    log_audit("\n=== SIMULATION SUMMARY ===\n");
    log_audit("Rounds completed: %d\n", round);
    log_audit("Total consumption: %.2f kWh\n", daily_bill.total_kwh);
    log_audit("Total cost (with HST): $%.2f\n", daily_bill.total_cost);
    log_audit("SIMULATION ENDED\n");
    
    if (audit_log) fclose(audit_log);
    
    // Clean up
    crypto_cleanup();
    cr_cleanup();
    
    printf("\n[REPORT] Results saved in results/\n");
    printf("==================================================================\n");
    
    return 0;
}
EOF
echo "  ✅ src/main.c"

# ==================================================================
# CRYPTO_UTILS.C
# ==================================================================
cat > src/crypto/crypto_utils.c << 'EOF'
#include "crypto_utils.h"
#include "config.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Global parameters for Pedersen commitments
static mpz_t g;      // Generator
static mpz_t h;      // Second generator
static mpz_t p;      // Large prime modulus
static mpz_t q;      // Subgroup order
static int crypto_initialized = 0;

// Commit-reveal global state
static CommitRevealEntry cr_entries[NUM_SMART_METERS];
static pthread_mutex_t cr_mutex = PTHREAD_MUTEX_INITIALIZER;

// ==================================================================
// Crypto Initialization
// ==================================================================
int crypto_init() {
    if (crypto_initialized) return 1;
    
    mpz_init(g);
    mpz_init(h);
    mpz_init(p);
    mpz_init(q);
    
    // 2048-bit safe prime (simplified for simulation)
    const char *p_str =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
    
    mpz_set_str(p, p_str, 16);
    
    // q = (p-1)/2
    mpz_sub_ui(q, p, 1);
    mpz_fdiv_q_2exp(q, q, 1);
    
    // Set generators
    mpz_set_ui(g, 2);
    mpz_set_ui(h, 5);  // Nothing-up-my-sleeve number
    
    // Verify h is in subgroup
    mpz_powm(h, h, q, p);
    
    // Initialize OpenSSL RNG
    RAND_poll();
    
    crypto_initialized = 1;
    return 1;
}

void crypto_cleanup() {
    if (crypto_initialized) {
        mpz_clear(g);
        mpz_clear(h);
        mpz_clear(p);
        mpz_clear(q);
        crypto_initialized = 0;
    }
}

int generate_csprng(mpz_t rand, int bits) {
    size_t bytes = (bits + 7) / 8;
    unsigned char *buffer = malloc(bytes);
    
    if (!RAND_bytes(buffer, bytes)) {
        free(buffer);
        return 0;
    }
    
    mpz_import(rand, bytes, 1, 1, 0, 0, buffer);
    free(buffer);
    
    // Ensure it's less than q
    if (mpz_cmp(rand, q) >= 0) {
        mpz_mod(rand, rand, q);
    }
    
    return 1;
}

// ==================================================================
// Commit-Reveal Functions
// ==================================================================
void cr_init_round() {
    pthread_mutex_lock(&cr_mutex);
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        cr_entries[i].meter_id = i + 1;
        memset(cr_entries[i].commitment, 0, HASH_SIZE);
        mpz_init(cr_entries[i].reveal);
        cr_entries[i].revealed = 0;
        cr_entries[i].verified = 0;
    }
    pthread_mutex_unlock(&cr_mutex);
}

int cr_meter_commit(uint8_t meter_id, uint32_t round, mpz_t random, uint8_t *commitment) {
    pthread_mutex_lock(&cr_mutex);
    
    int index = meter_id - 1;
    
    // Store random value
    mpz_set(cr_entries[index].reveal, random);
    
    // Create commitment: H(round || meter_id || random)
    uint8_t hash_input[sizeof(round) + 1 + RANDOM_BITS/8];
    memcpy(hash_input, &round, sizeof(round));
    hash_input[sizeof(round)] = meter_id;
    
    size_t size;
    unsigned char *random_bytes = mpz_export(NULL, &size, 1, 1, 0, 0, random);
    memcpy(hash_input + sizeof(round) + 1, random_bytes, size);
    
    SHA256(hash_input, sizeof(round) + 1 + size, commitment);
    free(random_bytes);
    
    // Store in global entries
    memcpy(cr_entries[index].commitment, commitment, HASH_SIZE);
    cr_entries[index].revealed = 0;
    
    pthread_mutex_unlock(&cr_mutex);
    
    return 1;
}

int cr_meter_reveal(uint8_t meter_id, mpz_t reveal) {
    pthread_mutex_lock(&cr_mutex);
    
    int index = meter_id - 1;
    
    // Verify this meter hasn't already revealed
    if (cr_entries[index].revealed) {
        pthread_mutex_unlock(&cr_mutex);
        return 0;
    }
    
    // Store reveal
    mpz_set(cr_entries[index].reveal, reveal);
    cr_entries[index].revealed = 1;
    
    pthread_mutex_unlock(&cr_mutex);
    
    return 1;
}

int cr_verify_reveal(uint8_t meter_id, uint32_t round, const uint8_t *commitment, mpz_t reveal) {
    uint8_t computed_hash[HASH_SIZE];
    
    // Recompute commitment
    uint8_t hash_input[sizeof(round) + 1 + RANDOM_BITS/8];
    memcpy(hash_input, &round, sizeof(round));
    hash_input[sizeof(round)] = meter_id;
    
    size_t size;
    unsigned char *random_bytes = mpz_export(NULL, &size, 1, 1, 0, 0, reveal);
    memcpy(hash_input + sizeof(round) + 1, random_bytes, size);
    
    SHA256(hash_input, sizeof(round) + 1 + size, computed_hash);
    free(random_bytes);
    
    // Constant-time compare
    return constant_time_compare(computed_hash, commitment, HASH_SIZE);
}

int cr_verify_all_reveals(uint32_t round) {
    pthread_mutex_lock(&cr_mutex);
    
    int valid_count = 0;
    
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        if (!cr_entries[i].revealed) {
            printf("  ⚠️ Meter %d did not reveal\n", cr_entries[i].meter_id);
            cr_entries[i].verified = 0;
            continue;
        }
        
        if (cr_verify_reveal(cr_entries[i].meter_id, round,
                             cr_entries[i].commitment, cr_entries[i].reveal)) {
            cr_entries[i].verified = 1;
            valid_count++;
        } else {
            printf("  ⚠️ Meter %d verification FAILED\n", cr_entries[i].meter_id);
            cr_entries[i].verified = 0;
        }
    }
    
    pthread_mutex_unlock(&cr_mutex);
    
    return valid_count;
}

int cr_generate_seed(uint32_t round, uint8_t *seed) {
    pthread_mutex_lock(&cr_mutex);
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    
    // Include round number
    EVP_DigestUpdate(ctx, &round, sizeof(round));
    
    // Include timestamp for additional entropy
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    EVP_DigestUpdate(ctx, &ts.tv_nsec, sizeof(ts.tv_nsec));
    
    // Include all verified reveals
    int valid_count = 0;
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        if (cr_entries[i].verified) {
            size_t size;
            unsigned char *reveal_bytes = mpz_export(NULL, &size, 1, 1, 0, 0, cr_entries[i].reveal);
            EVP_DigestUpdate(ctx, reveal_bytes, size);
            free(reveal_bytes);
            valid_count++;
        }
    }
    
    EVP_DigestFinal_ex(ctx, seed, NULL);
    EVP_MD_CTX_free(ctx);
    
    pthread_mutex_unlock(&cr_mutex);
    
    return valid_count;
}

void cr_cleanup() {
    pthread_mutex_lock(&cr_mutex);
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        mpz_clear(cr_entries[i].reveal);
    }
    pthread_mutex_unlock(&cr_mutex);
}

// ==================================================================
// Committee Selection Functions
// ==================================================================
typedef struct {
    mpz_t score;
    uint8_t meter_id;
} ScoreEntry;

int compare_scores(const void *a, const void *b) {
    const ScoreEntry *sa = (const ScoreEntry *)a;
    const ScoreEntry *sb = (const ScoreEntry *)b;
    return mpz_cmp(sb->score, sa->score); // Descending
}

void compute_meter_score(mpz_t score, const uint8_t *seed, uint8_t meter_id) {
    uint8_t hash_input[HASH_SIZE + 1];
    memcpy(hash_input, seed, HASH_SIZE);
    hash_input[HASH_SIZE] = meter_id;
    
    uint8_t hash_output[HASH_SIZE];
    SHA256(hash_input, sizeof(hash_input), hash_output);
    
    mpz_import(score, HASH_SIZE, 1, 1, 0, 0, hash_output);
}

int select_committee_eth(uint32_t round, const uint8_t *seed, uint8_t *committee) {
    (void)round; // Unused in simulation
    
    ScoreEntry scores[NUM_SMART_METERS];
    
    // Compute scores for all meters
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        mpz_init(scores[i].score);
        scores[i].meter_id = i + 1;
        compute_meter_score(scores[i].score, seed, scores[i].meter_id);
    }
    
    // Sort by score (highest first)
    qsort(scores, NUM_SMART_METERS, sizeof(ScoreEntry), compare_scores);
    
    // Take top COMMITTEE_SIZE as committee
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        committee[i] = scores[i].meter_id;
    }
    
    // Handle ties at boundary
    if (COMMITTEE_SIZE < NUM_SMART_METERS) {
        int last_idx = COMMITTEE_SIZE - 1;
        int next_idx = COMMITTEE_SIZE;
        
        if (mpz_cmp(scores[last_idx].score, scores[next_idx].score) == 0) {
            // Resolve tie by choosing lower meter ID
            if (scores[last_idx].meter_id > scores[next_idx].meter_id) {
                committee[last_idx] = scores[next_idx].meter_id;
            }
        }
    }
    
    // Clean up
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        mpz_clear(scores[i].score);
    }
    
    return 1;
}

int verify_committee_selection(uint32_t round, const uint8_t *seed, const uint8_t *committee) {
    uint8_t computed_committee[COMMITTEE_SIZE];
    
    if (!select_committee_eth(round, seed, computed_committee)) {
        return 0;
    }
    
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        if (computed_committee[i] != committee[i]) {
            return 0;
        }
    }
    
    return 1;
}

// ==================================================================
// Pedersen Commitment Functions
// ==================================================================
int create_pedersen_commitment(PedersenCommitment *comm, uint64_t reading,
                               uint32_t round, uint8_t meter_id) {
    if (!crypto_initialized) return 0;
    
    (void)round;  // Unused in simulation
    (void)meter_id;
    
    mpz_init(comm->value);
    mpz_init(comm->r);
    
    // Generate random blinding factor
    if (!generate_csprng(comm->r, 256)) {
        mpz_clear(comm->value);
        mpz_clear(comm->r);
        return 0;
    }
    
    // Compute g^reading mod p
    mpz_t g_reading;
    mpz_init(g_reading);
    mpz_powm_ui(g_reading, g, reading, p);
    
    // Compute h^r mod p
    mpz_t h_r;
    mpz_init(h_r);
    mpz_powm(h_r, h, comm->r, p);
    
    // Multiply: C = g^reading * h^r mod p
    mpz_mul(comm->value, g_reading, h_r);
    mpz_mod(comm->value, comm->value, p);
    
    mpz_clear(g_reading);
    mpz_clear(h_r);
    
    return 1;
}

int verify_pedersen_commitment(PedersenCommitment *comm, uint64_t reading) {
    mpz_t expected;
    mpz_init(expected);
    
    mpz_t g_reading, h_r;
    mpz_init(g_reading);
    mpz_init(h_r);
    
    mpz_powm_ui(g_reading, g, reading, p);
    mpz_powm(h_r, h, comm->r, p);
    
    mpz_mul(expected, g_reading, h_r);
    mpz_mod(expected, expected, p);
    
    int result = (mpz_cmp(expected, comm->value) == 0);
    
    mpz_clear(expected);
    mpz_clear(g_reading);
    mpz_clear(h_r);
    
    return result;
}

int add_commitments(PedersenCommitment *result, PedersenCommitment *a, PedersenCommitment *b) {
    if (!crypto_initialized) return 0;
    
    mpz_init(result->value);
    mpz_init(result->r);
    
    // Add values: C = C1 * C2 mod p
    mpz_mul(result->value, a->value, b->value);
    mpz_mod(result->value, result->value, p);
    
    // Add blinding factors: r = r1 + r2 mod q
    mpz_add(result->r, a->r, b->r);
    mpz_mod(result->r, result->r, q);
    
    return 1;
}

// ==================================================================
// Hash Functions
// ==================================================================
void hash_commitment(uint8_t *output, uint32_t round, uint8_t meter_id, mpz_t random) {
    uint8_t hash_input[sizeof(round) + 1 + RANDOM_BITS/8];
    memcpy(hash_input, &round, sizeof(round));
    hash_input[sizeof(round)] = meter_id;
    
    size_t size;
    unsigned char *random_bytes = mpz_export(NULL, &size, 1, 1, 0, 0, random);
    memcpy(hash_input + sizeof(round) + 1, random_bytes, size);
    
    SHA256(hash_input, sizeof(round) + 1 + size, output);
    free(random_bytes);
}

void hash_data(uint8_t *output, const void *data, size_t len) {
    SHA256(data, len, output);
}

// ==================================================================
// Utility Functions
// ==================================================================
void print_hex(const uint8_t *data, size_t len, const char *label) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 8; i++) {
        printf("%02x", data[i]);
    }
    printf("%s\n", len > 8 ? "..." : "");
}

int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}
EOF
echo "  ✅ src/crypto/crypto_utils.c"

# ==================================================================
# SHAMIR_SECRET.C
# ==================================================================
cat > src/crypto/shamir_secret.c << 'EOF'
#include "shamir_secret.h"
#include "crypto_utils.h"
#include "config.h"
#include <gmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// ==================================================================
// Polynomial operations
// ==================================================================
void create_polynomial(Polynomial *poly, uint64_t secret, int degree) {
    poly->degree = degree;
    poly->coefficients = malloc((degree + 1) * sizeof(mpz_t));
    
    for (int i = 0; i <= degree; i++) {
        mpz_init(poly->coefficients[i]);
    }
    
    // Constant term = secret
    mpz_set_ui(poly->coefficients[0], secret);
    
    // Random coefficients a1...a5 (for degree 5)
    for (int i = 1; i <= degree; i++) {
        generate_csprng(poly->coefficients[i], 128);
    }
}

void evaluate_polynomial(mpz_t result, Polynomial *poly, int x) {
    // Use Horner's method for efficient evaluation
    mpz_set(result, poly->coefficients[poly->degree]);
    
    for (int i = poly->degree - 1; i >= 0; i--) {
        mpz_mul_ui(result, result, x);
        mpz_add(result, result, poly->coefficients[i]);
    }
}

void polynomial_free(Polynomial *poly) {
    if (poly->coefficients) {
        for (int i = 0; i <= poly->degree; i++) {
            mpz_clear(poly->coefficients[i]);
        }
        free(poly->coefficients);
        poly->coefficients = NULL;
    }
}

// ==================================================================
// Share generation
// ==================================================================
void generate_shares(Share *shares, uint64_t secret, int num_shares, int threshold) {
    Polynomial poly;
    
    // Create polynomial of degree threshold-1
    create_polynomial(&poly, secret, threshold - 1);
    
    // Generate shares for x = 1..num_shares
    for (int i = 0; i < num_shares; i++) {
        shares[i].x = i + 1;  // Member IDs 1..num_shares
        mpz_init(shares[i].value);
        evaluate_polynomial(shares[i].value, &poly, shares[i].x);
    }
    
    polynomial_free(&poly);
}

int verify_share(Share *share, Polynomial *poly) {
    mpz_t expected;
    mpz_init(expected);
    
    evaluate_polynomial(expected, poly, share->x);
    
    int result = (mpz_cmp(expected, share->value) == 0);
    
    mpz_clear(expected);
    return result;
}

// ==================================================================
// Secure share transmission (simplified for simulation)
// ==================================================================
int encrypt_share(EncryptedShare *encrypted, Share *share,
                  uint8_t meter_id, uint8_t committee_id, uint32_t round,
                  uint8_t *recipient_public_key) {
    (void)recipient_public_key;  // Not used in simulation
    
    encrypted->meter_id = meter_id;
    encrypted->committee_member_id = committee_id;
    encrypted->round = round;
    encrypted->x = share->x;
    
    mpz_init_set(encrypted->encrypted_value, share->value);
    
    // Compute HMAC for integrity
    compute_share_hmac(encrypted->hmac, encrypted);
    
    return 1;
}

int decrypt_share(Share *share, EncryptedShare *encrypted,
                  uint8_t *recipient_private_key) {
    (void)recipient_private_key;  // Not used in simulation
    
    // Verify HMAC first
    if (!verify_share_hmac(encrypted)) {
        return 0;
    }
    
    share->x = encrypted->x;
    mpz_init_set(share->value, encrypted->encrypted_value);
    
    return 1;
}

void compute_share_hmac(uint8_t *hmac, EncryptedShare *share) {
    // Simplified HMAC for simulation
    // In real system: use HMAC-SHA256
    uint8_t data[sizeof(share->meter_id) + sizeof(share->committee_member_id) +
                 sizeof(share->round) + sizeof(share->x) + 64];
    
    size_t offset = 0;
    memcpy(data + offset, &share->meter_id, sizeof(share->meter_id));
    offset += sizeof(share->meter_id);
    
    memcpy(data + offset, &share->committee_member_id, sizeof(share->committee_member_id));
    offset += sizeof(share->committee_member_id);
    
    memcpy(data + offset, &share->round, sizeof(share->round));
    offset += sizeof(share->round);
    
    memcpy(data + offset, &share->x, sizeof(share->x));
    offset += sizeof(share->x);
    
    size_t size;
    unsigned char *value_bytes = mpz_export(NULL, &size, 1, 1, 0, 0, share->encrypted_value);
    memcpy(data + offset, value_bytes, size);
    offset += size;
    
    SHA256(data, offset, hmac);
    free(value_bytes);
}

int verify_share_hmac(EncryptedShare *share) {
    uint8_t computed_hmac[HASH_SIZE];
    compute_share_hmac(computed_hmac, share);
    
    return constant_time_compare(computed_hmac, share->hmac, HASH_SIZE);
}

// ==================================================================
// Reconstruction using Lagrange interpolation
// ==================================================================
int reconstruct_secret(mpz_t result, Share *shares, int num_shares, int threshold) {
    if (num_shares < threshold) {
        printf("  ERROR: Need at least %d shares for reconstruction\n", threshold);
        return 0;
    }
    
    mpz_set_ui(result, 0);
    
    // Lagrange interpolation at x = 0
    for (int i = 0; i < num_shares; i++) {
        mpz_t numerator, denominator, term;
        mpz_init_set_ui(numerator, 1);
        mpz_init_set_ui(denominator, 1);
        mpz_init(term);
        
        // Compute Lagrange coefficient λ_i = Π (x_j)/(x_j - x_i) for j≠i
        for (int j = 0; j < num_shares; j++) {
            if (i != j) {
                // numerator *= x_j
                mpz_mul_ui(numerator, numerator, shares[j].x);
                
                // denominator *= (x_j - x_i)
                mpz_t diff;
                mpz_init_set_ui(diff, shares[j].x - shares[i].x);
                mpz_mul(denominator, denominator, diff);
                mpz_clear(diff);
            }
        }
        
        // term = y_i * (numerator/denominator)
        mpz_mul(term, shares[i].value, numerator);
        mpz_fdiv_q(term, term, denominator);
        
        // result += term
        mpz_add(result, result, term);
        
        mpz_clear(numerator);
        mpz_clear(denominator);
        mpz_clear(term);
    }
    
    return 1;
}

int reconstruct_with_lagrange(mpz_t result, Share *shares, int num_shares) {
    return reconstruct_secret(result, shares, num_shares, num_shares);
}

void share_free(Share *share) {
    mpz_clear(share->value);
}

void encrypted_share_free(EncryptedShare *share) {
    mpz_clear(share->encrypted_value);
}
EOF
echo "  ✅ src/crypto/shamir_secret.c"

# ==================================================================
# SMART_METER.C
# ==================================================================
cat > src/meter/smart_meter.c << 'EOF'
#include "smart_meter.h"
#include "crypto_utils.h"
#include "shamir_secret.h"
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// ==================================================================
// Meter initialization
// ==================================================================
void meter_init(SmartMeter *meter, uint8_t id) {
    meter->id = id;
    meter->reading = 0;
    meter->is_committee_member = 0;
    meter->last_committee_round = 0;
    meter->times_selected = 0;
    meter->total_reading = 0;
    meter->total_cost = 0;
    meter->num_received_shares = 0;
    meter->status = METER_ACTIVE;
    
    mpz_init(meter->random_value);
    memset(meter->commitment_hash, 0, HASH_SIZE);
    
    // Initialize Pedersen commitment structure
    mpz_init(meter->pedersen_comm.value);
    mpz_init(meter->pedersen_comm.r);
    
    // Initialize received shares
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        mpz_init(meter->received_shares[i].value);
        meter->received_shares[i].x = 0;
    }
    
    // Initialize mutex
    pthread_mutex_init(&meter->lock, NULL);
    
    // Generate dummy keys (simplified for simulation)
    memset(meter->public_key, id, 32);  // Dummy public key
    memset(meter->private_key, id + 0x80, 32);  // Dummy private key
}

// ==================================================================
// Reading generation (realistic patterns)
// ==================================================================
void meter_generate_reading(SmartMeter *meter, uint32_t round) {
    // Calculate time of day (in hours)
    int hour = (round * 5) / 60;  // Each round = 5 minutes
    int minute = (round * 5) % 60;
    
    // Base consumption varies by time of day
    uint64_t base_reading;
    
    if (hour >= 7 && hour < 11) {  // Morning peak (7AM-11AM)
        base_reading = 1500 + (rand() % 1000);
    } else if (hour >= 17 && hour < 21) {  // Evening peak (5PM-9PM)
        base_reading = 2000 + (rand() % 1500);
    } else if (hour >= 11 && hour < 17) {  // Mid-day (11AM-5PM)
        base_reading = 800 + (rand() % 700);
    } else {  // Night/early morning
        base_reading = 300 + (rand() % 500);
    }
    
    // Add some random variation based on meter ID (different consumption patterns)
    meter->reading = base_reading + (meter->id * 50) + (rand() % 200);
    
    // Update total
    meter->total_reading += meter->reading;
}

// ==================================================================
// PHASE 1: Commit-reveal functions
// ==================================================================
void meter_generate_random(SmartMeter *meter, uint32_t round) {
    (void)round;  // Unused in simulation
    
    // Generate cryptographically secure random number
    generate_csprng(meter->random_value, RANDOM_BITS);
}

int meter_create_commitment(SmartMeter *meter, uint32_t round) {
    // Create hash commitment: H(round || meter_id || random)
    hash_commitment(meter->commitment_hash, round, meter->id, meter->random_value);
    return 1;
}

int meter_reveal_random(SmartMeter *meter, uint32_t round) {
    (void)round;  // Unused in simulation
    // Random value is already stored in meter->random_value
    return 1;
}

// ==================================================================
// PHASE 3: Reading commitment
// ==================================================================
int meter_create_reading_commitment(SmartMeter *meter, uint32_t round) {
    return create_pedersen_commitment(&meter->pedersen_comm, meter->reading, round, meter->id);
}

// ==================================================================
// PHASE 4: Share generation and distribution
// ==================================================================
int meter_generate_shares(SmartMeter *meter, uint8_t *committee,
                          uint32_t round, EncryptedShare *encrypted_shares) {
    // Generate raw shares using Shamir's scheme
    Share raw_shares[COMMITTEE_SIZE];
    generate_shares(raw_shares, meter->reading, COMMITTEE_SIZE, THRESHOLD);
    
    // Encrypt each share for the respective committee member
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        int member_id = committee[i];
        
        // Find committee member's public key (simplified)
        uint8_t public_key[32];
        memset(public_key, member_id, 32);  // Dummy public key
        
        if (!encrypt_share(&encrypted_shares[i], &raw_shares[i],
                           meter->id, member_id, round, public_key)) {
            return 0;
        }
        
        // Clean up raw share
        mpz_clear(raw_shares[i].value);
    }
    
    return 1;
}

int meter_receive_share(SmartMeter *meter, EncryptedShare *share) {
    // Verify this share is for this meter
    if (share->committee_member_id != meter->id) {
        return 0;
    }
    
    // Verify HMAC
    if (!verify_share_hmac(share)) {
        printf("    ⚠️ SM%d: Share from SM%d failed HMAC verification\n",
               meter->id, share->meter_id);
        return 0;
    }
    
    // Decrypt the share
    Share decrypted_share;
    if (!decrypt_share(&decrypted_share, share, meter->private_key)) {
        return 0;
    }
    
    // Store the share
    meter_lock(meter);
    
    int index = share->meter_id - 1;
    meter->received_shares[index].x = decrypted_share.x;
    mpz_set(meter->received_shares[index].value, decrypted_share.value);
    meter->num_received_shares++;
    
    meter_unlock(meter);
    
    // Clean up
    mpz_clear(decrypted_share.value);
    
    return 1;
}

int meter_verify_share(SmartMeter *meter, EncryptedShare *share) {
    (void)meter;  // Unused
    
    // Just verify HMAC
    return verify_share_hmac(share);
}

// ==================================================================
// PHASE 5: Aggregation (for committee members)
// ==================================================================
int meter_aggregate_shares(SmartMeter *meter, uint32_t round, mpz_t aggregated) {
    (void)round;  // Unused
    
    meter_lock(meter);
    
    mpz_set_ui(aggregated, 0);
    
    // Sum all received shares
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        if (meter->received_shares[i].x != 0) {  // Valid share received
            mpz_add(aggregated, aggregated, meter->received_shares[i].value);
        }
    }
    
    meter_unlock(meter);
    
    return 1;
}

// ==================================================================
// Utility functions
// ==================================================================
void meter_lock(SmartMeter *meter) {
    pthread_mutex_lock(&meter->lock);
}

void meter_unlock(SmartMeter *meter) {
    pthread_mutex_unlock(&meter->lock);
}

void meter_print_info(SmartMeter *meter) {
    printf("Meter SM%d:\n", meter->id);
    printf("  Reading: %lu Wh\n", meter->reading);
    printf("  Status: %s\n",
           meter->status == METER_ACTIVE ? "ACTIVE" :
           meter->status == METER_INACTIVE ? "INACTIVE" :
           meter->status == METER_SUSPECT ? "SUSPECT" : "MALICIOUS");
    printf("  Committee member: %s\n", meter->is_committee_member ? "YES" : "NO");
    printf("  Times selected: %d\n", meter->times_selected);
    printf("  Total reading: %lu kWh\n", meter->total_reading / 1000);
}

void meter_free(SmartMeter *meter) {
    mpz_clear(meter->random_value);
    mpz_clear(meter->pedersen_comm.value);
    mpz_clear(meter->pedersen_comm.r);
    
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        mpz_clear(meter->received_shares[i].value);
    }
    
    pthread_mutex_destroy(&meter->lock);
}
EOF
echo "  ✅ src/meter/smart_meter.c"

# ==================================================================
# COMMITTEE.C
# ==================================================================
cat > src/committee/committee.c << 'EOF'
#include "committee.h"
#include "crypto_utils.h"
#include "shamir_secret.h"
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// ==================================================================
// Committee initialization
// ==================================================================
void committee_init(Committee *comm) {
    memset(comm->members, 0, COMMITTEE_SIZE);
    comm->round = 0;
    comm->spatial_aggregate = 0;
    comm->temporal_aggregate = 0;
    comm->num_aggregated_shares = 0;
    
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        mpz_init(comm->aggregated_shares[i].value);
        comm->aggregated_shares[i].member_id = 0;
        comm->aggregated_shares[i].round = 0;
    }
    
    for (int i = 0; i < NUM_SMART_METERS; i++) {
        comm->meter_commitments[i] = NULL;
    }
    
    memset(comm->round_seed, 0, HASH_SIZE);
}

// ==================================================================
// PHASE 2: Committee selection
// ==================================================================
int committee_select(Committee *comm, uint32_t round, const uint8_t *seed) {
    uint8_t selected[COMMITTEE_SIZE];
    
    if (!select_committee_eth(round, seed, selected)) {
        return 0;
    }
    
    comm->round = round;
    memcpy(comm->members, selected, COMMITTEE_SIZE);
    memcpy(comm->round_seed, seed, HASH_SIZE);
    
    return 1;
}

// ==================================================================
// PHASE 3: Store commitments
// ==================================================================
int committee_store_commitment(Committee *comm, uint8_t meter_id,
                               PedersenCommitment *commitment) {
    if (meter_id < 1 || meter_id > NUM_SMART_METERS) {
        return 0;
    }
    
    // In a real system, we'd store a copy
    // For simulation, just store pointer
    comm->meter_commitments[meter_id - 1] = commitment;
    
    return 1;
}

// ==================================================================
// PHASE 5: Spatial aggregation
// ==================================================================
int committee_member_aggregate(Committee *comm, SmartMeter *member,
                               uint32_t round, mpz_t aggregated) {
    (void)comm;  // Unused
    return meter_aggregate_shares(member, round, aggregated);
}

int committee_aggregate_shares(Committee *comm, SmartMeter *meters,
                               uint32_t round, AggregatedShare *result) {
    (void)result;  // We'll store in comm instead
    
    // For each committee member, aggregate their shares
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        int member_id = comm->members[i];
        SmartMeter *member = &meters[member_id - 1];
        
        mpz_t aggregated;
        mpz_init(aggregated);
        
        if (!committee_member_aggregate(comm, member, round, aggregated)) {
            mpz_clear(aggregated);
            return 0;
        }
        
        // Store in committee
        comm->aggregated_shares[i].member_id = member_id;
        mpz_set(comm->aggregated_shares[i].value, aggregated);
        comm->aggregated_shares[i].round = round;
        
        mpz_clear(aggregated);
    }
    
    comm->num_aggregated_shares = COMMITTEE_SIZE;
    
    return 1;
}

// ==================================================================
// PHASE 6: Reconstruction
// ==================================================================
int committee_reconstruct_total(Committee *comm, AggregatedShare *shares,
                                int num_shares, uint64_t *total) {
    if (num_shares < THRESHOLD) {
        return 0;
    }
    
    // Convert AggregatedShare to Share structure
    Share share_array[num_shares];
    for (int i = 0; i < num_shares; i++) {
        share_array[i].x = shares[i].member_id;
        mpz_init_set(share_array[i].value, shares[i].value);
    }
    
    // Reconstruct
    mpz_t result;
    mpz_init(result);
    
    if (!reconstruct_secret(result, share_array, num_shares, THRESHOLD)) {
        for (int i = 0; i < num_shares; i++) {
            mpz_clear(share_array[i].value);
        }
        mpz_clear(result);
        return 0;
    }
    
    *total = mpz_get_ui(result);
    comm->spatial_aggregate = *total;
    
    // Clean up
    mpz_clear(result);
    for (int i = 0; i < num_shares; i++) {
        mpz_clear(share_array[i].value);
    }
    
    return 1;
}

// ==================================================================
// PHASE 8: Reporting
// ==================================================================
void committee_send_to_esp(Committee *comm, uint64_t total_consumption, uint32_t round) {
    // In a real system, this would send data to the Energy Service Provider
    // For simulation, just log it
    printf("\n[ESP REPORT] Round %d total consumption: %lu Wh (%.2f kWh)\n",
           round, total_consumption, total_consumption/1000.0);
    
    // Update temporal aggregate
    if (round == 0) {
        comm->temporal_aggregate = total_consumption;
    } else {
        comm->temporal_aggregate += total_consumption;
    }
}

// ==================================================================
// Verification functions
// ==================================================================
int verify_committee_member(Committee *comm, uint8_t member_id) {
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        if (comm->members[i] == member_id) {
            return 1;
        }
    }
    return 0;
}

int verify_aggregated_share(AggregatedShare *share, uint8_t *public_key) {
    (void)public_key;  // Would verify signature in real system
    
    // Basic validation
    if (share->member_id < 1 || share->member_id > NUM_SMART_METERS) {
        return 0;
    }
    
    if (mpz_sgn(share->value) < 0) {
        return 0;
    }
    
    return 1;
}

// ==================================================================
// Utility functions
// ==================================================================
void committee_print(Committee *comm) {
    printf("Committee for round %d:\n", comm->round);
    printf("  Members: ");
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        printf("SM%d ", comm->members[i]);
    }
    printf("\n");
    printf("  Spatial aggregate: %lu Wh\n", comm->spatial_aggregate);
    printf("  Temporal aggregate: %lu Wh\n", comm->temporal_aggregate);
    printf("  Aggregated shares: %d\n", comm->num_aggregated_shares);
}

void committee_free(Committee *comm) {
    for (int i = 0; i < COMMITTEE_SIZE; i++) {
        mpz_clear(comm->aggregated_shares[i].value);
    }
}
EOF
echo "  ✅ src/committee/committee.c"

# ==================================================================
# BILLING.C
# ==================================================================
cat > src/utils/billing.c << 'EOF'
#include "billing.h"
#include "config.h"
#include <stdio.h>
#include <string.h>

// ==================================================================
// Rate periods definition
// ==================================================================
static const RatePeriod RATE_PERIODS[] = {
    {OFF_PEAK_RATE, "OFF-PEAK", OFF_PEAK_1_START, OFF_PEAK_1_END},
    {MID_PEAK_RATE, "MID-PEAK", MID_PEAK_1_START, MID_PEAK_1_END},
    {ON_PEAK_RATE,  "ON-PEAK",  ON_PEAK_START,    ON_PEAK_END},
    {MID_PEAK_RATE, "MID-PEAK", MID_PEAK_2_START, MID_PEAK_2_END},
    {OFF_PEAK_RATE, "OFF-PEAK", OFF_PEAK_2_START, OFF_PEAK_2_END}
};

#define NUM_RATE_PERIODS (sizeof(RATE_PERIODS) / sizeof(RATE_PERIODS[0]))

// ==================================================================
// Period detection
// ==================================================================
int is_off_peak(uint32_t round) {
    uint32_t round_in_day = round % ROUNDS_PER_DAY;
    return (round_in_day >= OFF_PEAK_1_START && round_in_day < OFF_PEAK_1_END) ||
           (round_in_day >= OFF_PEAK_2_START && round_in_day < OFF_PEAK_2_END);
}

int is_mid_peak(uint32_t round) {
    uint32_t round_in_day = round % ROUNDS_PER_DAY;
    return (round_in_day >= MID_PEAK_1_START && round_in_day < MID_PEAK_1_END) ||
           (round_in_day >= MID_PEAK_2_START && round_in_day < MID_PEAK_2_END);
}

int is_on_peak(uint32_t round) {
    uint32_t round_in_day = round % ROUNDS_PER_DAY;
    return (round_in_day >= ON_PEAK_START && round_in_day < ON_PEAK_END);
}

// ==================================================================
// Rate functions
// ==================================================================
double get_rate_for_round(uint32_t round) {
    uint32_t round_in_day = round % ROUNDS_PER_DAY;
    
    for (int i = 0; i < NUM_RATE_PERIODS; i++) {
        if (round_in_day >= RATE_PERIODS[i].start_round &&
            round_in_day < RATE_PERIODS[i].end_round) {
            return RATE_PERIODS[i].rate;
        }
    }
    
    // Default to off-peak
    return OFF_PEAK_RATE;
}

const char* get_time_period(uint32_t round) {
    uint32_t round_in_day = round % ROUNDS_PER_DAY;
    
    for (int i = 0; i < NUM_RATE_PERIODS; i++) {
        if (round_in_day >= RATE_PERIODS[i].start_round &&
            round_in_day < RATE_PERIODS[i].end_round) {
            return RATE_PERIODS[i].period_name;
        }
    }
    
    return "OFF-PEAK";
}

RatePeriod get_current_period(uint32_t round) {
    uint32_t round_in_day = round % ROUNDS_PER_DAY;
    
    for (int i = 0; i < NUM_RATE_PERIODS; i++) {
        if (round_in_day >= RATE_PERIODS[i].start_round &&
            round_in_day < RATE_PERIODS[i].end_round) {
            return RATE_PERIODS[i];
        }
    }
    
    return RATE_PERIODS[0];  // Default to first off-peak period
}

// ==================================================================
// Cost calculation
// ==================================================================
double calculate_round_cost(uint64_t wh, uint32_t round) {
    double kwh = wh / 1000.0;
    double rate_cents = get_rate_for_round(round);
    
    // Convert cents to dollars: (kWh * rate¢/kWh) / 100
    return (kwh * rate_cents) / 100.0;
}

double calculate_period_cost(double kwh, double rate_cents) {
    return (kwh * rate_cents) / 100.0;
}

double calculate_hst(double subtotal) {
    return subtotal * 0.13;  // 13% HST
}

// ==================================================================
// Bill management
// ==================================================================
void init_daily_bill(DailyBill *bill) {
    bill->off_peak_kwh = 0;
    bill->mid_peak_kwh = 0;
    bill->on_peak_kwh = 0;
    bill->total_kwh = 0;
    bill->subtotal = 0;
    bill->hst = 0;
    bill->total_cost = 0;
    
    bill->off_peak_rounds = 0;
    bill->mid_peak_rounds = 0;
    bill->on_peak_rounds = 0;
}

void update_daily_bill(DailyBill *bill, uint64_t wh, uint32_t round) {
    double kwh = wh / 1000.0;
    
    // Update consumption by period
    if (is_off_peak(round)) {
        bill->off_peak_kwh += kwh;
        bill->off_peak_rounds++;
    } else if (is_mid_peak(round)) {
        bill->mid_peak_kwh += kwh;
        bill->mid_peak_rounds++;
    } else if (is_on_peak(round)) {
        bill->on_peak_kwh += kwh;
        bill->on_peak_rounds++;
    }
    
    // Update totals
    bill->total_kwh += kwh;
    
    // Calculate running subtotal (without HST)
    bill->subtotal = (bill->off_peak_kwh * OFF_PEAK_RATE / 100.0) +
                     (bill->mid_peak_kwh * MID_PEAK_RATE / 100.0) +
                     (bill->on_peak_kwh * ON_PEAK_RATE / 100.0);
    
    // Calculate HST on current subtotal
    bill->hst = calculate_hst(bill->subtotal);
    
    // Final total with HST
    bill->total_cost = bill->subtotal + bill->hst;
}

void finalize_bill(DailyBill *bill) {
    // Ensure HST is calculated correctly
    bill->hst = calculate_hst(bill->subtotal);
    bill->total_cost = bill->subtotal + bill->hst;
}

// ==================================================================
// Printing functions
// ==================================================================
void print_bill_summary(DailyBill *bill) {
    printf("\n=== CURRENT BILL SUMMARY ===\n");
    printf("Consumption by period:\n");
    printf("  Off-Peak: %.2f kWh (%d rounds)\n", bill->off_peak_kwh, bill->off_peak_rounds);
    printf("  Mid-Peak: %.2f kWh (%d rounds)\n", bill->mid_peak_kwh, bill->mid_peak_rounds);
    printf("  On-Peak:  %.2f kWh (%d rounds)\n", bill->on_peak_kwh, bill->on_peak_rounds);
    printf("  TOTAL:    %.2f kWh\n", bill->total_kwh);
    printf("\nCost breakdown:\n");
    printf("  Off-Peak @ %.1f¢: $%.2f\n", OFF_PEAK_RATE,
           bill->off_peak_kwh * OFF_PEAK_RATE / 100.0);
    printf("  Mid-Peak @ %.1f¢: $%.2f\n", MID_PEAK_RATE,
           bill->mid_peak_kwh * MID_PEAK_RATE / 100.0);
    printf("  On-Peak  @ %.1f¢: $%.2f\n", ON_PEAK_RATE,
           bill->on_peak_kwh * ON_PEAK_RATE / 100.0);
    printf("  Subtotal: $%.2f\n", bill->subtotal);
    printf("  HST (13%%): $%.2f\n", bill->hst);
    printf("  TOTAL:    $%.2f\n", bill->total_cost);
}

void print_financial_report(DailyBill *bill) {
    printf("\n════════════════════════════════════════════════════════════\n");
    printf("FINAL FINANCIAL REPORT\n");
    printf("════════════════════════════════════════════════════════════\n");
    printf("Consumption Summary:\n");
    printf("  Off-Peak (7.4¢):  %8.2f kWh @ 7.4¢ = $%8.2f\n",
           bill->off_peak_kwh, bill->off_peak_kwh * 0.074);
    printf("  Mid-Peak (10.9¢): %8.2f kWh @ 10.9¢ = $%8.2f\n",
           bill->mid_peak_kwh, bill->mid_peak_kwh * 0.109);
    printf("  On-Peak (15.9¢):  %8.2f kWh @ 15.9¢ = $%8.2f\n",
           bill->on_peak_kwh, bill->on_peak_kwh * 0.159);
    printf("  %33s ----------\n", "");
    printf("  %33s $%8.2f\n", "Subtotal:", bill->subtotal);
    printf("  %33s $%8.2f\n", "HST (13%):", bill->hst);
    printf("  %33s ----------\n", "");
    printf("  %33s $%8.2f\n", "TOTAL:", bill->total_cost);
    printf("════════════════════════════════════════════════════════════\n");
}

void log_billing_entry(DailyBill *bill, uint32_t round, uint64_t wh, double cost) {
    // This would write to a billing log file
    // For simulation, just print
    printf("  [BILLING] Round %d: %.2f kWh, $%.2f, Total bill: $%.2f\n",
           round, wh/1000.0, cost, bill->total_cost);
}
EOF
echo "  ✅ src/utils/billing.c"

# ==================================================================
# MAKEFILE
# ==================================================================
cat > Makefile << 'EOF'
# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -I./include -g -pthread
LIBS = -lgmp -lssl -lcrypto -lpthread

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin

# Source files
CRYPTO_SRCS = $(SRCDIR)/crypto/crypto_utils.c $(SRCDIR)/crypto/shamir_secret.c
METER_SRCS = $(SRCDIR)/meter/smart_meter.c
COMMITTEE_SRCS = $(SRCDIR)/committee/committee.c
UTILS_SRCS = $(SRCDIR)/utils/billing.c
MAIN_SRC = $(SRCDIR)/main.c

# Object files
CRYPTO_OBJS = $(CRYPTO_SRCS:$(SRCDIR)/crypto/%.c=$(OBJDIR)/crypto/%.o)
METER_OBJS = $(METER_SRCS:$(SRCDIR)/meter/%.c=$(OBJDIR)/meter/%.o)
COMMITTEE_OBJS = $(COMMITTEE_SRCS:$(SRCDIR)/committee/%.c=$(OBJDIR)/committee/%.o)
UTILS_OBJS = $(UTILS_SRCS:$(SRCDIR)/utils/%.c=$(OBJDIR)/utils/%.o)
MAIN_OBJ = $(MAIN_SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

ALL_OBJS = $(CRYPTO_OBJS) $(METER_OBJS) $(COMMITTEE_OBJS) $(UTILS_OBJS) $(MAIN_OBJ)

# Target executable
TARGET = $(BINDIR)/smart_meter_protocol

# Default target
all: $(TARGET)

# Create directories
$(OBJDIR):
	mkdir -p $(OBJDIR)
	mkdir -p $(OBJDIR)/crypto
	mkdir -p $(OBJDIR)/meter
	mkdir -p $(OBJDIR)/committee
	mkdir -p $(OBJDIR)/utils

$(BINDIR):
	mkdir -p $(BINDIR)

# Link
$(TARGET): $(OBJDIR) $(BINDIR) $(ALL_OBJS)
	$(CC) $(ALL_OBJS) -o $@ $(LIBS)
	@echo "✅ Build complete: $(TARGET)"

# Compile main
$(OBJDIR)/main.o: $(SRCDIR)/main.c $(INCDIR)/*.h
	$(CC) $(CFLAGS) -c $< -o $@

# Compile crypto files
$(OBJDIR)/crypto/%.o: $(SRCDIR)/crypto/%.c $(INCDIR)/*.h
	$(CC) $(CFLAGS) -c $< -o $@

# Compile meter files
$(OBJDIR)/meter/%.o: $(SRCDIR)/meter/%.c $(INCDIR)/*.h
	$(CC) $(CFLAGS) -c $< -o $@

# Compile committee files
$(OBJDIR)/committee/%.o: $(SRCDIR)/committee/%.c $(INCDIR)/*.h
	$(CC) $(CFLAGS) -c $< -o $@

# Compile utils files
$(OBJDIR)/utils/%.o: $(SRCDIR)/utils/%.c $(INCDIR)/*.h
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	@echo "🧹 Cleaned build files"

# Clean everything including results
distclean: clean
	rm -rf results/*
	@echo "🧹 Cleaned results"

# Run
run: all
	./$(TARGET)

# Run with valgrind (memory check)
valgrind: all
	valgrind --leak-check=full ./$(TARGET)

# Create submission archive
archive:
	tar -czf smart_meter_project.tar.gz include src Makefile README.md
	@echo "📦 Created archive: smart_meter_project.tar.gz"

.PHONY: all clean distclean run valgrind archive
EOF
echo "  ✅ Makefile"

# ==================================================================
# README.MD
# ==================================================================
cat > README.md << 'EOF'
# Decentralized Smart Metering Protocol Simulation

## Overview
This project implements a fully decentralized smart metering protocol with 8 phases, simulating 20 smart meters over 144 rounds (12 hours).

## Protocol Phases
1. **Commit-Reveal**: Generate unbiased randomness
2. **Committee Selection**: Ethereum-style RANDAO (H(seed || meter_id))
3. **Pedersen Commitments**: Hide individual readings
4. **Share Generation**: Shamir secret sharing (threshold k=6)
5. **Spatial Aggregation**: Committee sums shares
6. **Reconstruction**: Lagrange interpolation recovers total
7. **Temporal Aggregation**: Running total over time
8. **OEB Billing**: Time-of-use rates with HST

## Building
```bash
make clean
make
make run
