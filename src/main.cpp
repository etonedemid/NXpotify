#include <atomic>
#include <mutex>
#include <cstdio>
#include <thread>
#include <wut.h>
#include <whb/proc.h>
#include <whb/log.h>
#include <whb/log_udp.h>
#include <whb/sdcard.h>
#include <nn/ac.h>
#include <nsysnet/nssl.h>
#include <curl/curl.h>
#include <coreinit/time.h>
#include <coreinit/thread.h>

#include "connect/player.h"

// ── SD card log sink ──────────────────────────────────────────────────────────
// Every WHBLogPrint/WHBLogPrintf call is forwarded here and immediately flushed
// so the log survives a crash. File is created/truncated on each launch.
// Path: SD:/spotify_log.txt

static FILE       *s_log_file = nullptr;
static std::mutex  s_log_mu;

static void file_log_handler(const char *msg) {
    std::lock_guard<std::mutex> lk(s_log_mu);
    if (!s_log_file) return;
    fputs(msg, s_log_file);
    fputc('\n', s_log_file);
    fflush(s_log_file);
}

int main(int /*argc*/, char ** /*argv*/) {
    WHBProcInit();
    WHBLogUdpInit();
    WHBMountSdCard();

    // Open log file on SD card (overwrite each launch so users get a clean log).
    const char *sd = WHBGetSdCardMountPath();
    if (sd) {
        char path[256];
        snprintf(path, sizeof(path), "%s/spotify_log.txt", sd);
        s_log_file = fopen(path, "w");
    }
    WHBAddLogHandler(file_log_handler);

    WHBLogPrint("spotify-wiiu: starting");

    // Network stack init blocks for several seconds — keep ProcUI alive while
    // waiting by pumping WHBProcIsRunning() from the main thread.
    std::atomic<bool> net_ready{false};
    std::thread net_thread([&] {
        ACInitialize();
        ACConnect();
        NSSLInit();
        curl_global_init(CURL_GLOBAL_ALL);
        net_ready.store(true, std::memory_order_release);
        WHBLogPrint("spotify-wiiu: network ready");
    });

    while (!net_ready.load(std::memory_order_acquire) && WHBProcIsRunning())
        OSSleepTicks(OSMillisecondsToTicks(16));

    if (WHBProcIsRunning()) {
        Connect::Player player;
        player.run();   // blocks until HOME button / system exit
    }

    net_thread.join();
    curl_global_cleanup();
    NSSLFinish();
    ACFinalize();

    WHBRemoveLogHandler(file_log_handler);
    {
        std::lock_guard<std::mutex> lk(s_log_mu);
        if (s_log_file) { fclose(s_log_file); s_log_file = nullptr; }
    }

    WHBUnmountSdCard();
    WHBLogUdpDeinit();
    WHBProcShutdown();
    return 0;
}
