/*
 * replay.c - Replay Attack Protection Implementation
 * ===================================================
 */

#include "replay.h"
#include "../util/memory.h"

void replay_init(replay_state *state)
{
    vpn_memzero(state, sizeof(*state));
    state->highest = 0;
    state->initialized = false;
}

void replay_reset(replay_state *state)
{
    replay_init(state);
}

bool replay_check_only(const replay_state *state, uint64_t counter)
{
    uint64_t diff;
    size_t index;
    uint64_t bit;

    /* First packet always accepted */
    if (!state->initialized) {
        return true;
    }

    /* Counter ahead of window: would be accepted */
    if (counter > state->highest) {
        return true;
    }

    /* Counter too old: would be rejected */
    diff = state->highest - counter;
    if (diff >= REPLAY_WINDOW_SIZE) {
        return false;
    }

    /* Check bitmap */
    index = (counter / 64) % REPLAY_BITMAP_SIZE;
    bit = 1ULL << (counter % 64);

    return (state->bitmap[index] & bit) == 0;
}

bool replay_check(replay_state *state, uint64_t counter)
{
    uint64_t diff;
    size_t index;
    uint64_t bit;
    size_t i;

    /* First packet: initialize state */
    if (!state->initialized) {
        state->highest = counter;
        index = (counter / 64) % REPLAY_BITMAP_SIZE;
        bit = 1ULL << (counter % 64);
        state->bitmap[index] = bit;
        state->initialized = true;
        return true;
    }

    /* Counter ahead of current highest */
    if (counter > state->highest) {
        diff = counter - state->highest;

        if (diff >= REPLAY_WINDOW_SIZE) {
            /*
             * Counter jumped way ahead - clear entire bitmap.
             * This can happen after long periods of inactivity.
             */
            vpn_memzero(state->bitmap, sizeof(state->bitmap));
        } else {
            /*
             * Clear bits for counters between old highest and new.
             * We iterate through the positions that are now outside the window.
             */
            for (i = 1; i < diff && i < REPLAY_WINDOW_SIZE; i++) {
                uint64_t clear_counter = state->highest + i;
                size_t clear_index = (clear_counter / 64) % REPLAY_BITMAP_SIZE;
                uint64_t clear_bit = 1ULL << (clear_counter % 64);

                /*
                 * Only clear if this counter is now outside the new window.
                 * Actually, we need to clear the slots that will wrap around.
                 */
                if (clear_index == ((counter / 64) % REPLAY_BITMAP_SIZE)) {
                    /* This slot will be reused, clear old bits */
                    state->bitmap[clear_index] = 0;
                }
            }

            /*
             * Simpler approach: clear the bits that would overlap.
             * For small advances, this is fine. For large advances,
             * we already cleared everything above.
             */
            if (diff < REPLAY_WINDOW_SIZE) {
                /* Clear bits between highest+1 and counter-1 */
                for (i = state->highest + 1; i < counter; i++) {
                    index = (i / 64) % REPLAY_BITMAP_SIZE;
                    bit = 1ULL << (i % 64);
                    state->bitmap[index] &= ~bit;
                }
            }
        }

        /* Update highest and mark this counter */
        state->highest = counter;
        index = (counter / 64) % REPLAY_BITMAP_SIZE;
        bit = 1ULL << (counter % 64);
        state->bitmap[index] |= bit;

        return true;
    }

    /* Counter is at or below highest */
    diff = state->highest - counter;

    /* Too old: outside the window */
    if (diff >= REPLAY_WINDOW_SIZE) {
        return false;
    }

    /* Check if already seen */
    index = (counter / 64) % REPLAY_BITMAP_SIZE;
    bit = 1ULL << (counter % 64);

    if (state->bitmap[index] & bit) {
        /* Already seen - replay */
        return false;
    }

    /* Mark as seen and accept */
    state->bitmap[index] |= bit;
    return true;
}
