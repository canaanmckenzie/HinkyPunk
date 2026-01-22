/*
 * replay.h - Replay Attack Protection
 * ====================================
 *
 * This module implements sliding window replay protection for transport
 * packets. Without replay protection, an attacker could record encrypted
 * packets and replay them later, potentially causing duplicate operations.
 *
 * HOW REPLAY ATTACKS WORK:
 *
 *   1. Attacker records encrypted packet P at time T1
 *   2. At time T2, attacker sends P again
 *   3. Without protection, receiver decrypts and processes P again
 *
 * Even though the attacker can't decrypt or modify P, replaying it might:
 *   - Cause duplicate transactions
 *   - Reset state
 *   - Consume resources
 *
 * SLIDING WINDOW APPROACH:
 *
 * Each packet has a monotonically increasing counter (nonce). We track:
 *   - highest_seen: The largest counter we've received
 *   - bitmap: A window of WINDOW_SIZE bits tracking recent counters
 *
 * For a counter N:
 *   - If N > highest_seen: Accept, update highest_seen, mark in bitmap
 *   - If N <= highest_seen - WINDOW_SIZE: Reject (too old)
 *   - Otherwise: Check bitmap; reject if already seen, accept if new
 *
 * WINDOW SIZE:
 *
 * WireGuard uses WINDOW_SIZE=2048. This handles:
 *   - Out-of-order packets within the window
 *   - Packet loss and retransmission
 *   - Network jitter
 *
 * The window should be sized based on expected network conditions.
 * Too small = false rejections. Too large = memory usage.
 */

#ifndef VPN_REPLAY_H
#define VPN_REPLAY_H

#include "../types.h"

/*
 * Window size in bits (must be multiple of 64 for efficient storage)
 * 2048 bits = 256 bytes, covers counters [highest-2047, highest]
 */
#define REPLAY_WINDOW_SIZE  2048
#define REPLAY_BITMAP_SIZE  (REPLAY_WINDOW_SIZE / 64)

/*
 * Replay protection state
 *
 * Tracks which packet counters have been seen within the sliding window.
 */
typedef struct {
    uint64_t highest;                       /* Highest counter seen */
    uint64_t bitmap[REPLAY_BITMAP_SIZE];    /* Bitmap of seen counters */
    bool initialized;                        /* Has first packet been seen? */
} replay_state;

/*
 * replay_init - Initialize replay protection state
 *
 * @param state     State to initialize
 */
void replay_init(replay_state *state);

/*
 * replay_check - Check if a counter has been seen (and mark it)
 *
 * This is the core function. It atomically checks and marks a counter.
 *
 * @param state     Replay protection state
 * @param counter   Packet counter to check
 * @return          true if counter is valid (not replayed), false if replay
 *
 * USAGE:
 *   if (!replay_check(&session->replay, packet_counter)) {
 *       LOG_WARN("Replay detected, dropping packet");
 *       return;
 *   }
 *   // Process packet...
 *
 * THREAD SAFETY: This function is NOT thread-safe. The caller must ensure
 * exclusive access to the state, typically via a session lock.
 */
bool replay_check(replay_state *state, uint64_t counter);

/*
 * replay_check_only - Check without marking (for validation)
 *
 * @param state     Replay protection state
 * @param counter   Packet counter to check
 * @return          true if counter would be accepted
 */
bool replay_check_only(const replay_state *state, uint64_t counter);

/*
 * replay_reset - Reset replay state
 *
 * Called when rekeying to start fresh with new transport keys.
 *
 * @param state     State to reset
 */
void replay_reset(replay_state *state);

#endif /* VPN_REPLAY_H */
