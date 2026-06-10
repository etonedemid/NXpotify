#include <atomic>
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

int main(int /*argc*/, char ** /*argv*/) {
    WHBProcInit();
    WHBLogUdpInit();
    WHBMountSdCard();
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

    WHBUnmountSdCard();
    WHBLogUdpDeinit();
    WHBProcShutdown();
    return 0;
}
