#pragma once
// Platform abstraction: Nintendo Switch (libnx/devkitA64)
// All Wii U-specific (wut/whb/coreinit) APIs are replaced here.

#include <sys/select.h>
#include <stdint.h>
#include <stdio.h>

#include <switch.h>

// ── Logging ───────────────────────────────────────────────────────────────────
// print(msg)       → PLAT_LOG(msg)
// printf(fmt, ...) → PLAT_LOGF(fmt, ...)
#define PLAT_LOG(msg)        (printf("%s\n", (msg)))
#define PLAT_LOGF(fmt, ...)  (printf(fmt "\n", ##__VA_ARGS__))

// ── Sleep ─────────────────────────────────────────────────────────────────────
// OSSleepTicks(OSMillisecondsToTicks(N)) → plat_sleep_ms(N)
static inline void plat_sleep_ms(int ms) {
    svcSleepThread((u64)ms * 1000000ULL);
}

// ── System ticks (19.2 MHz ARM arch counter) ──────────────────────────────────
// OSGetSystemTick()        → plat_ticks()
// OSMillisecondsToTicks(N) → plat_ms_to_ticks(N)
// OSSecondsToTicks(N)      → plat_s_to_ticks(N)
static inline uint64_t plat_ticks()              { return armGetSystemTick(); }
static inline uint64_t plat_ms_to_ticks(int ms)  { return (uint64_t)ms * 19200ULL; }
static inline uint64_t plat_s_to_ticks(int s)    { return (uint64_t)s  * 19200000ULL; }
static inline int64_t  plat_now_ms()             { return (int64_t)(armGetSystemTick() / 19200ULL); }

// ── Main-loop predicate ───────────────────────────────────────────────────────
// WHBProcIsRunning() → plat_running()
static inline bool plat_running() { return appletMainLoop(); }

// ── Thread affinity (no-op on Switch; ARM has no core pinning via POSIX) ──────
// OSSetThreadAffinity(...) → just delete the call
#define PLAT_PIN_CPU0()  do {} while (0)
#define PLAT_PIN_CPU1()  do {} while (0)
#define PLAT_PIN_CPU2()  do {} while (0)

// ── SD card root ──────────────────────────────────────────────────────────────
// Wii U: /vol/external01/   Switch: sdmc:/
#define SD_ROOT "sdmc:"

// ── Math ──────────────────────────────────────────────────────────────────────
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
