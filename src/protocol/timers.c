/*
 * timers.c - Timer Management Implementation
 * ==========================================
 */

#include "timers.h"
#include "peer.h"
#include "../util/memory.h"
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/time.h>
#endif

/*
 * ===========================================================================
 * Time Utilities
 * ===========================================================================
 */

static time_t get_time_ms(void)
{
#ifdef _WIN32
    return (time_t)GetTickCount64();
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (time_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
#endif
}

/*
 * ===========================================================================
 * Timer Manager
 * ===========================================================================
 */

void timers_init(timer_manager *tm, timer_callback_fn callback, void *userdata)
{
    vpn_memzero(tm, sizeof(*tm));
    tm->callback = callback;
    tm->callback_userdata = userdata;
    tm->current_tick = get_time_ms();
    tm->initialized = true;
}

void timers_shutdown(timer_manager *tm)
{
    int i;

    if (!tm->initialized) return;

    /* Remove all timers */
    for (i = 0; i < 256; i++) {
        timer_entry *entry = tm->wheel[i].head;
        while (entry) {
            timer_entry *next = entry->next;
            entry->active = false;
            entry->next = NULL;
            entry->prev = NULL;
            entry = next;
        }
        tm->wheel[i].head = NULL;
    }

    tm->initialized = false;
}

static void timer_remove_from_bucket(timer_manager *tm, timer_entry *entry)
{
    size_t bucket_idx;

    if (!entry->active) return;

    bucket_idx = (entry->expires / 1000) % 256;

    if (entry->prev) {
        entry->prev->next = entry->next;
    } else {
        tm->wheel[bucket_idx].head = entry->next;
    }

    if (entry->next) {
        entry->next->prev = entry->prev;
    }

    entry->prev = NULL;
    entry->next = NULL;
    entry->active = false;
}

static void timer_add_to_bucket(timer_manager *tm, timer_entry *entry)
{
    size_t bucket_idx;

    bucket_idx = (entry->expires / 1000) % 256;

    entry->next = tm->wheel[bucket_idx].head;
    entry->prev = NULL;

    if (tm->wheel[bucket_idx].head) {
        tm->wheel[bucket_idx].head->prev = entry;
    }

    tm->wheel[bucket_idx].head = entry;
    entry->active = true;
}

int timers_process(timer_manager *tm)
{
    time_t now = get_time_ms();
    int processed = 0;
    size_t bucket_idx;
    timer_entry *entry, *next;

    if (!tm->initialized) return 0;

    /* Process buckets up to current time */
    while (tm->current_tick <= now) {
        bucket_idx = (tm->current_tick / 1000) % 256;

        entry = tm->wheel[bucket_idx].head;
        while (entry) {
            next = entry->next;

            if (entry->expires <= now) {
                /* Timer expired */
                timer_remove_from_bucket(tm, entry);

                if (tm->callback && entry->peer) {
                    tm->callback(entry->peer, entry->type, tm->callback_userdata);
                }

                processed++;
            }

            entry = next;
        }

        tm->current_tick += 1000;  /* Move to next second bucket */
    }

    tm->current_tick = now;
    return processed;
}

int timers_next_deadline(timer_manager *tm)
{
    time_t now = get_time_ms();
    time_t earliest = 0;
    int i;
    timer_entry *entry;
    bool found = false;

    if (!tm->initialized) return -1;

    for (i = 0; i < 256; i++) {
        entry = tm->wheel[i].head;
        while (entry) {
            if (!found || entry->expires < earliest) {
                earliest = entry->expires;
                found = true;
            }
            entry = entry->next;
        }
    }

    if (!found) return -1;

    if (earliest <= now) return 0;
    return (int)(earliest - now);
}

/*
 * ===========================================================================
 * Timer Entry Operations
 * ===========================================================================
 */

void timer_init(timer_entry *entry, struct peer_t *peer, timer_type_t type)
{
    vpn_memzero(entry, sizeof(*entry));
    entry->peer = peer;
    entry->type = type;
    entry->active = false;
}

void timer_schedule(timer_manager *tm, timer_entry *entry, uint32_t delay_ms)
{
    if (!tm->initialized) return;

    /* Remove if already scheduled */
    if (entry->active) {
        timer_remove_from_bucket(tm, entry);
    }

    entry->expires = get_time_ms() + delay_ms;
    timer_add_to_bucket(tm, entry);
}

void timer_schedule_sec(timer_manager *tm, timer_entry *entry, uint32_t delay_sec)
{
    timer_schedule(tm, entry, delay_sec * 1000);
}

void timer_cancel(timer_manager *tm, timer_entry *entry)
{
    if (!tm->initialized) return;

    if (entry->active) {
        timer_remove_from_bucket(tm, entry);
    }
}

bool timer_is_active(const timer_entry *entry)
{
    return entry->active;
}

/*
 * ===========================================================================
 * Peer Timer Helpers
 * ===========================================================================
 */

/* These would integrate with peer.h - providing function stubs here */

void timers_data_sent(timer_manager *tm, struct peer_t *peer)
{
    UNUSED(tm);
    UNUSED(peer);
    /* Would reset keepalive timer for peer */
}

void timers_data_received(timer_manager *tm, struct peer_t *peer)
{
    UNUSED(tm);
    UNUSED(peer);
    /* Would reset keepalive timer for peer */
}

void timers_handshake_initiated(timer_manager *tm, struct peer_t *peer)
{
    UNUSED(tm);
    UNUSED(peer);
    /* Would set handshake timeout */
}

void timers_handshake_complete(timer_manager *tm, struct peer_t *peer)
{
    UNUSED(tm);
    UNUSED(peer);
    /* Would cancel handshake timeout, set rekey timer */
}

void timers_session_derived(timer_manager *tm, struct peer_t *peer)
{
    UNUSED(tm);
    UNUSED(peer);
    /* Would set session expiration timer */
}
