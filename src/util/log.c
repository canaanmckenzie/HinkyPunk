/*
 * log.c - Logging System Implementation
 * ======================================
 */

#include "log.h"
#include "memory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <syslog.h>
    #include <pthread.h>
#endif

/*
 * ===========================================================================
 * Global State
 * ===========================================================================
 */

static struct {
    log_level_t level;
    int outputs;
    FILE *file;
    log_callback_fn callback;
    void *callback_userdata;
    bool initialized;

#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
} g_log = {
    .level = LOG_LEVEL_INFO,
    .outputs = LOG_OUTPUT_STDERR,
    .file = NULL,
    .callback = NULL,
    .callback_userdata = NULL,
    .initialized = false
};

/*
 * ===========================================================================
 * Thread Safety
 * ===========================================================================
 */

static void log_lock(void)
{
    if (!g_log.initialized) return;

#ifdef _WIN32
    EnterCriticalSection(&g_log.lock);
#else
    pthread_mutex_lock(&g_log.lock);
#endif
}

static void log_unlock(void)
{
    if (!g_log.initialized) return;

#ifdef _WIN32
    LeaveCriticalSection(&g_log.lock);
#else
    pthread_mutex_unlock(&g_log.lock);
#endif
}

/*
 * ===========================================================================
 * Initialization
 * ===========================================================================
 */

vpn_error_t log_init(log_level_t level, int outputs)
{
#ifdef _WIN32
    InitializeCriticalSection(&g_log.lock);
#else
    pthread_mutex_init(&g_log.lock, NULL);
#endif

    g_log.level = level;
    g_log.outputs = outputs;
    g_log.initialized = true;

#ifndef _WIN32
    if (outputs & LOG_OUTPUT_SYSLOG) {
        openlog("vpn", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }
#endif

    return VPN_OK;
}

void log_set_level(log_level_t level)
{
    g_log.level = level;
}

log_level_t log_get_level(void)
{
    return g_log.level;
}

vpn_error_t log_set_file(const char *path)
{
    log_lock();

    if (g_log.file && g_log.file != stderr && g_log.file != stdout) {
        fclose(g_log.file);
        g_log.file = NULL;
    }

    if (path) {
        g_log.file = fopen(path, "a");
        if (!g_log.file) {
            log_unlock();
            return VPN_ERR_CONFIG;
        }
        /* Line-buffered for log files */
        setvbuf(g_log.file, NULL, _IOLBF, 0);
    }

    log_unlock();
    return VPN_OK;
}

void log_set_callback(log_callback_fn callback, void *userdata)
{
    log_lock();
    g_log.callback = callback;
    g_log.callback_userdata = userdata;
    log_unlock();
}

void log_shutdown(void)
{
    log_lock();

    if (g_log.file && g_log.file != stderr && g_log.file != stdout) {
        fclose(g_log.file);
        g_log.file = NULL;
    }

#ifndef _WIN32
    if (g_log.outputs & LOG_OUTPUT_SYSLOG) {
        closelog();
    }
#endif

    g_log.initialized = false;
    log_unlock();

#ifdef _WIN32
    DeleteCriticalSection(&g_log.lock);
#else
    pthread_mutex_destroy(&g_log.lock);
#endif
}

/*
 * ===========================================================================
 * Log Level Strings
 * ===========================================================================
 */

static const char *level_string(log_level_t level)
{
    switch (level) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_WARN:  return "WARN ";
        case LOG_LEVEL_INFO:  return "INFO ";
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_TRACE: return "TRACE";
        default:              return "?????";
    }
}

#ifndef _WIN32
static int level_to_syslog(log_level_t level)
{
    switch (level) {
        case LOG_LEVEL_ERROR: return LOG_ERR;
        case LOG_LEVEL_WARN:  return LOG_WARNING;
        case LOG_LEVEL_INFO:  return LOG_INFO;
        case LOG_LEVEL_DEBUG: return LOG_DEBUG;
        case LOG_LEVEL_TRACE: return LOG_DEBUG;
        default:              return LOG_INFO;
    }
}
#endif

/*
 * ===========================================================================
 * Timestamp Generation
 * ===========================================================================
 */

static void get_timestamp(char *buf, size_t len)
{
    time_t now = time(NULL);
    struct tm *tm_info;

#ifdef _WIN32
    struct tm tm_storage;
    localtime_s(&tm_storage, &now);
    tm_info = &tm_storage;
#else
    struct tm tm_storage;
    tm_info = localtime_r(&now, &tm_storage);
#endif

    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

/*
 * ===========================================================================
 * Core Logging
 * ===========================================================================
 */

void log_message(log_level_t level, const char *file, int line,
                 const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_message_v(level, file, line, fmt, args);
    va_end(args);
}

void log_message_v(log_level_t level, const char *file, int line,
                   const char *fmt, va_list args)
{
    char timestamp[32];
    char message[4096];
    const char *filename;
    int len;

    /* Check level */
    if (level > g_log.level || level == LOG_LEVEL_NONE) {
        return;
    }

    /* Format message */
    len = vsnprintf(message, sizeof(message), fmt, args);
    if (len < 0) {
        return;
    }

    /* Extract filename from path */
    filename = strrchr(file, '/');
    if (!filename) filename = strrchr(file, '\\');
    filename = filename ? filename + 1 : file;

    /* Get timestamp */
    get_timestamp(timestamp, sizeof(timestamp));

    log_lock();

    /* Output to stderr */
    if (g_log.outputs & LOG_OUTPUT_STDERR) {
        if (level <= LOG_LEVEL_DEBUG) {
            fprintf(stderr, "[%s] %s: %s\n", timestamp, level_string(level), message);
        } else {
            /* Include file:line for TRACE */
            fprintf(stderr, "[%s] %s: %s:%d: %s\n",
                    timestamp, level_string(level), filename, line, message);
        }
        fflush(stderr);
    }

    /* Output to file */
    if ((g_log.outputs & LOG_OUTPUT_FILE) && g_log.file) {
        fprintf(g_log.file, "[%s] %s: %s:%d: %s\n",
                timestamp, level_string(level), filename, line, message);
        fflush(g_log.file);
    }

    /* Output to syslog */
#ifndef _WIN32
    if (g_log.outputs & LOG_OUTPUT_SYSLOG) {
        syslog(level_to_syslog(level), "%s", message);
    }
#endif

    /* Output to callback */
    if ((g_log.outputs & LOG_OUTPUT_CALLBACK) && g_log.callback) {
        g_log.callback(level, file, line, message, g_log.callback_userdata);
    }

    log_unlock();
}

void log_hexdump(log_level_t level, const char *label,
                 const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    char line[128];
    char *out;
    size_t i, j;

    if (level > g_log.level) {
        return;
    }

    LOG_DEBUG("%s (%zu bytes):", label, len);

    for (i = 0; i < len; i += 16) {
        out = line;
        out += sprintf(out, "  %04zx: ", i);

        /* Hex bytes */
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                out += sprintf(out, "%02x ", p[i + j]);
            } else {
                out += sprintf(out, "   ");
            }
            if (j == 7) *out++ = ' ';
        }

        /* ASCII representation */
        *out++ = ' ';
        *out++ = '|';
        for (j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = p[i + j];
            *out++ = (c >= 32 && c < 127) ? c : '.';
        }
        *out++ = '|';
        *out = '\0';

        log_message(level, __FILE__, __LINE__, "%s", line);
    }
}
