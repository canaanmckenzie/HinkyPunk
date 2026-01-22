/*
 * timers.h - Timer Management for VPN Sessions
 * =============================================
 *
 * This module manages the various timers required for proper VPN operation:
 *
 * TIMER TYPES:
 *
 * 1. REKEY_TIMEOUT: Time between session key rotations
 *    - Default: 120 seconds (REKEY_AFTER_TIME)
 *    - After this, initiate a new handshake
 *
 * 2. REKEY_ATTEMPT: Interval between handshake retry attempts
 *    - Default: 5 seconds (REKEY_TIMEOUT)
 *    - If handshake fails, retry after this interval
 *
 * 3. KEEPALIVE: Time between keepalive packets when idle
 *    - Default: Disabled (0), or user-configured (e.g., 25 seconds)
 *    - Maintains NAT mappings and detects dead connections
 *
 * 4. HANDSHAKE_TIMEOUT: Maximum time for handshake completion
 *    - Default: 5 seconds
 *    - Abort and retry if no response
 *
 * 5. REJECT_AFTER: Maximum session lifetime before forced rekey
 *    - Default: 180 seconds (REJECT_AFTER_TIME)
 *    - Hard limit even if rekey hasn't completed
 *
 * TIMER WHEEL IMPLEMENTATION:
 *
 * For efficiency with many peers, we use a hierarchical timer wheel:
 * - Coarse wheel: 256 buckets, 1 second resolution
 * - Fine wheel: 256 buckets, ~4ms resolution (within 1 second)
 *
 * This allows O(1) timer insertion and efficient batch expiration.
 */

#ifndef VPN_TIMERS_H
#define VPN_TIMERS_H

#include "../types.h"
#include <time.h>

/* Forward declarations */
struct peer_t;

/*
 * Timer event types
 */
typedef enum {
    TIMER_NONE = 0,
    TIMER_REKEY,            /* Time to initiate rekey */
    TIMER_REKEY_ATTEMPT,    /* Retry handshake */
    TIMER_KEEPALIVE,        /* Send keepalive packet */
    TIMER_HANDSHAKE,        /* Handshake timeout */
    TIMER_SESSION_EXPIRE,   /* Session expired */
    TIMER_ZERO_KEY,         /* Zero out old keys */
} timer_type_t;

/*
 * Timer callback function
 *
 * @param peer      Peer this timer belongs to
 * @param type      Timer type that fired
 * @param userdata  User-provided data
 */
typedef void (*timer_callback_fn)(struct peer_t *peer, timer_type_t type,
                                  void *userdata);

/*
 * Individual timer entry
 */
typedef struct timer_entry {
    struct timer_entry *next;   /* Linked list in bucket */
    struct timer_entry *prev;
    struct peer_t *peer;        /* Associated peer */
    timer_type_t type;          /* Timer type */
    time_t expires;             /* Expiration time (absolute) */
    bool active;                /* Is timer scheduled? */
} timer_entry;

/*
 * Timer wheel bucket
 */
typedef struct {
    timer_entry *head;
} timer_bucket;

/*
 * Timer manager state
 */
typedef struct {
    timer_bucket wheel[256];    /* Timer wheel buckets */
    time_t current_tick;        /* Current wheel position */
    timer_callback_fn callback; /* Callback for expired timers */
    void *callback_userdata;
    bool initialized;
} timer_manager;

/*
 * ===========================================================================
 * Timer Manager Operations
 * ===========================================================================
 */

/*
 * timers_init - Initialize timer manager
 *
 * @param tm        Timer manager to initialize
 * @param callback  Function to call when timers expire
 * @param userdata  User data for callback
 */
void timers_init(timer_manager *tm, timer_callback_fn callback, void *userdata);

/*
 * timers_shutdown - Clean up timer manager
 *
 * @param tm        Timer manager to clean up
 */
void timers_shutdown(timer_manager *tm);

/*
 * timers_process - Process expired timers
 *
 * Should be called periodically (e.g., every 100ms or on each main loop).
 * Invokes callbacks for all timers that have expired.
 *
 * @param tm        Timer manager
 * @return          Number of timers processed
 */
int timers_process(timer_manager *tm);

/*
 * timers_next_deadline - Get time until next timer expires
 *
 * Useful for select()/poll() timeout.
 *
 * @param tm        Timer manager
 * @return          Milliseconds until next timer, or -1 if no timers
 */
int timers_next_deadline(timer_manager *tm);

/*
 * ===========================================================================
 * Timer Entry Operations
 * ===========================================================================
 */

/*
 * timer_init - Initialize a timer entry
 *
 * @param entry     Timer entry to initialize
 * @param peer      Associated peer
 * @param type      Timer type
 */
void timer_init(timer_entry *entry, struct peer_t *peer, timer_type_t type);

/*
 * timer_schedule - Schedule a timer
 *
 * @param tm        Timer manager
 * @param entry     Timer entry
 * @param delay_ms  Delay in milliseconds
 */
void timer_schedule(timer_manager *tm, timer_entry *entry, uint32_t delay_ms);

/*
 * timer_schedule_sec - Schedule a timer (seconds)
 *
 * @param tm        Timer manager
 * @param entry     Timer entry
 * @param delay_sec Delay in seconds
 */
void timer_schedule_sec(timer_manager *tm, timer_entry *entry, uint32_t delay_sec);

/*
 * timer_cancel - Cancel a scheduled timer
 *
 * @param tm        Timer manager
 * @param entry     Timer entry to cancel
 */
void timer_cancel(timer_manager *tm, timer_entry *entry);

/*
 * timer_is_active - Check if timer is scheduled
 *
 * @param entry     Timer entry
 * @return          true if timer is active
 */
bool timer_is_active(const timer_entry *entry);

/*
 * ===========================================================================
 * Peer Timer Helpers
 * ===========================================================================
 */

/*
 * timers_peer_init - Initialize all timers for a peer
 *
 * @param tm        Timer manager
 * @param peer      Peer to initialize timers for
 */
void timers_peer_init(timer_manager *tm, struct peer_t *peer);

/*
 * timers_data_sent - Called when data is sent to peer
 *
 * Resets keepalive timer.
 *
 * @param tm        Timer manager
 * @param peer      Peer data was sent to
 */
void timers_data_sent(timer_manager *tm, struct peer_t *peer);

/*
 * timers_data_received - Called when data is received from peer
 *
 * Resets keepalive timer.
 *
 * @param tm        Timer manager
 * @param peer      Peer data was received from
 */
void timers_data_received(timer_manager *tm, struct peer_t *peer);

/*
 * timers_handshake_initiated - Called when handshake is initiated
 *
 * Sets handshake timeout.
 *
 * @param tm        Timer manager
 * @param peer      Peer handshake was initiated with
 */
void timers_handshake_initiated(timer_manager *tm, struct peer_t *peer);

/*
 * timers_handshake_complete - Called when handshake completes
 *
 * Cancels handshake timeout, sets rekey timer.
 *
 * @param tm        Timer manager
 * @param peer      Peer handshake completed with
 */
void timers_handshake_complete(timer_manager *tm, struct peer_t *peer);

/*
 * timers_session_derived - Called when session keys are derived
 *
 * Sets session expiration timer.
 *
 * @param tm        Timer manager
 * @param peer      Peer with new session
 */
void timers_session_derived(timer_manager *tm, struct peer_t *peer);

#endif /* VPN_TIMERS_H */
