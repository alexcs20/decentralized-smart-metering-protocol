#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// Protocol configuration
#define NUM_SMART_METERS 20
#define COMMITTEE_SIZE 10
#define THRESHOLD 6
#define ROUND_DURATION 1  // 1 second for fast simulation
#define ROUNDS_PER_HOUR 12
#define ROUNDS_PER_DAY 288
#define MAX_ROUNDS 144    // Run for half day (12 hours)

// Ontario Electricity Board (OEB) Rates (¢ per kWh) - 2024
#define OFF_PEAK_RATE 7.4
#define MID_PEAK_RATE 10.9
#define ON_PEAK_RATE 15.9

// Time periods (in rounds since midnight)
#define OFF_PEAK_START 0
#define MID_PEAK_START 84     // 7:00 AM
#define ON_PEAK_START 132      // 11:00 AM
#define MID_PEAK_END 192       // 4:00 PM
#define ON_PEAK_END 216        // 7:00 PM
#define OFF_PEAK_END 288

// Cryptographic parameters
#define PRIME_BITS 2048        // 2048-bit prime for security
#define HASH_SIZE 32           // SHA-256 produces 32 bytes
#define RANDOM_BITS 128        // 128 bits of randomness

// Network settings
#define BROADCAST_DELAY 1
#define REVEAL_TIMEOUT 3
#define COMMIT_TIMEOUT 2
#define MAX_MESSAGE_SIZE 4096

#endif
