/*
 * log.h - Logging System
 * =======================
 *
 * Structured logging for the VPN daemon with support for multiple log levels,
 * output destinations, and optional timestamps.
 *
 * LOG LEVELS:
 *
 *   ERROR   - Critical errors that may cause termination
 *   WARN    - Warnings that should be investigated
 *   INFO    - Normal operational messages
 *   DEBUG   - Detailed debugging information
 *   TRACE   - Very verbose, packet-level tracing
 *
 * USAGE:
 *
 *   log_init(LOG_LEVEL_INFO, LOG_OUTPUT_STDERR);
 *   LOG_INFO("Server started on port %d", port);
 *   LOG_ERROR("Failed to bind: %s", strerror(errno));
 *   LOG_DEBUG("Received %zu bytes from %s", len, addr);
 *
 * The macros automatically include file/line for DEBUG and TRACE levels.
 */

#ifndef VPN_LOG_H
#define VPN_LOG_H

#include "../types.h"
#include <stdarg.h>

/*
 * Log levels (in order of severity)
 */
typedef enum {
    LOG_LEVEL_NONE  = 0,    /* Disable all logging */
    LOG_LEVEL_ERROR = 1,    /* Errors only */
    LOG_LEVEL_WARN  = 2,    /* Warnings and above */
    LOG_LEVEL_INFO  = 3,    /* Informational and above */
    LOG_LEVEL_DEBUG = 4,    /* Debug and above */
    LOG_LEVEL_TRACE = 5     /* Everything */
} log_level_t;

/*
 * Log output destinations
 */
typedef enum {
    LOG_OUTPUT_NONE     = 0,
    LOG_OUTPUT_STDERR   = 1,
    LOG_OUTPUT_FILE     = 2,
    LOG_OUTPUT_SYSLOG   = 4,
    LOG_OUTPUT_CALLBACK = 8
} log_output_t;

/*
 * Log callback function type
 *
 * For custom log handling (e.g., sending to remote server).
 */
typedef void (*log_callback_fn)(log_level_t level, const char *file, int line,
                                const char *message, void *userdata);

/*
 * ===========================================================================
 * Initialization
 * ===========================================================================
 */

/*
 * log_init - Initialize logging system
 *
 * @param level     Minimum level to log (messages below this are ignored)
 * @param outputs   Bitmask of output destinations
 * @return          VPN_OK on success
 */
vpn_error_t log_init(log_level_t level, int outputs);

/*
 * log_set_level - Change log level at runtime
 *
 * @param level     New minimum level
 */
void log_set_level(log_level_t level);

/*
 * log_set_file - Set log file path
 *
 * @param path      Path to log file (NULL to disable file logging)
 * @return          VPN_OK on success
 */
vpn_error_t log_set_file(const char *path);

/*
 * log_set_callback - Set custom log callback
 *
 * @param callback  Callback function
 * @param userdata  User data passed to callback
 */
void log_set_callback(log_callback_fn callback, void *userdata);

/*
 * log_shutdown - Clean up logging system
 */
void log_shutdown(void);

/*
 * ===========================================================================
 * Logging Functions
 * ===========================================================================
 */

/*
 * log_message - Log a message (internal, use macros instead)
 *
 * @param level     Log level
 * @param file      Source file name
 * @param line      Source line number
 * @param fmt       Format string
 * @param ...       Format arguments
 */
void log_message(log_level_t level, const char *file, int line,
                 const char *fmt, ...) __attribute__((format(printf, 4, 5)));

/*
 * log_message_v - Log with va_list (for wrappers)
 */
void log_message_v(log_level_t level, const char *file, int line,
                   const char *fmt, va_list args);

/*
 * log_hexdump - Log a hexdump of binary data
 *
 * @param level     Log level
 * @param label     Label for the dump
 * @param data      Data to dump
 * @param len       Data length
 */
void log_hexdump(log_level_t level, const char *label,
                 const void *data, size_t len);

/*
 * ===========================================================================
 * Logging Macros
 * ===========================================================================
 *
 * These macros provide a convenient interface and automatically include
 * file/line information for debugging.
 */

#define LOG_ERROR(fmt, ...) \
    log_message(LOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    log_message(LOG_LEVEL_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    log_message(LOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_DEBUG(fmt, ...) \
    log_message(LOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_TRACE(fmt, ...) \
    log_message(LOG_LEVEL_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/*
 * Conditional logging (for performance-sensitive paths)
 */
#define LOG_DEBUG_ENABLED() (log_get_level() >= LOG_LEVEL_DEBUG)
#define LOG_TRACE_ENABLED() (log_get_level() >= LOG_LEVEL_TRACE)

log_level_t log_get_level(void);

#endif /* VPN_LOG_H */
