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
