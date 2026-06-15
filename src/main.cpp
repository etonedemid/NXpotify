#include <cstdio>
#include <switch.h>
#include <curl/curl.h>

#include "platform.h"
#include "connect/player.h"

int main(int /*argc*/, char ** /*argv*/) {
    freopen("sdmc:/nxpotify_log.txt", "w", stdout);
    setvbuf(stdout, nullptr, _IONBF, 0);

    PLAT_LOG("step1: socket");
    socketInitializeDefault();
    PLAT_LOG("step2: curl");
    curl_global_init(CURL_GLOBAL_ALL);
    PLAT_LOG("step3: player ctor");

    PLAT_LOG("NXpotify: starting");

    {
        Connect::Player player;
        player.run();
    }

    curl_global_cleanup();
    socketExit();
    return 0;
}
