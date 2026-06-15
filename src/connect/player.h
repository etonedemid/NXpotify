#pragma once
#include <cstdint>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <pthread.h>
#include <vector>
#include <string>
#include "../discovery/zeroconf.h"
#include "../ui/display.h"

// Forward declarations -- full headers pulled in player.cpp only
namespace Connect { class AP; class Spirc; class AudioPipeline; }

namespace Connect {

// Top-level state machine.  player.run() is the main loop.
//
//   WaitingForUser  ← Zeroconf running, mDNS announcing, no credentials yet
//         ↓           (Spotify app taps the device)
//   Connecting      ← AP TCP connect, Shannon handshake, login
//         ↓
//   Ready           ← Spirc subscribed, waiting for play command
//         ↓
//   Playing         ← audio pipeline active, chunks fetching+decoding
//
// Any state can return to WaitingForUser if the AP disconnects or
// the user revokes access.

class Player {
public:
    Player();
    ~Player();

    void run();   // blocks until appletMainLoop() returns false

private:
    void on_credentials(Discovery::Credentials creds);

    // Spirc callbacks (invoked from AP recv thread)
    void on_play(const std::string &track_uri, int position_ms);
    void on_file_ready(const std::vector<uint8_t> &file_id,
                       const std::vector<uint8_t> &track_gid,
                       int position_ms);
    void on_seek(int position_ms);
    void on_volume(int volume_pct);
    void on_track_changed(const std::string &title, const std::string &artist,
                          const std::string &art_url, int64_t duration_ms, bool is_explicit,
                          const std::string &track_id, const std::string &isrc);

    // Receives every AP packet not handled internally by AP (AesKey, Mercury, …)
    void on_ap_packet(uint8_t cmd, std::vector<uint8_t> payload);

    // First-time Spotify auth via device code + QR.  Called in a background
    // thread when no saved credentials exist on the SD card.
    void device_auth();

    // Switch controller input (called each frame from run())
    void handle_buttons(uint32_t trigger);
    // Switch touchscreen input (called each frame from run())
    void handle_touch();

    struct TouchState {
        bool    active   = false;
        bool    consumed = false;  // action already dispatched for this touch
        int16_t start_x  = 0;
        int16_t start_y  = 0;
        int16_t cur_x    = 0;
        int16_t cur_y    = 0;
    };
    TouchState touch_;

    enum class State { WaitingForUser, Connecting, Ready, Playing };
    std::atomic<State>    state_{State::WaitingForUser};
    std::atomic<uint32_t> ap_gen_{0};  // incremented each time a new AP is created

    Discovery::Zeroconf              zeroconf_;
    std::unique_ptr<AP>              ap_;
    std::unique_ptr<Spirc>           spirc_;
    std::unique_ptr<AudioPipeline>   audio_;
    UI::Display                      display_;

    int            volume_           = 100;
    bool           spirc_playing_    = false;
    int            track_dur_ms_     = 0;
    std::string    track_title_;
    std::string    track_artist_;
    std::string    track_id_;
    std::string    isrc_;
    bool           track_explicit_   = false;
    bool           crystal_enabled_  = false;
    int            crystal_strength_ = 5;     // 1-10

    // Pending audio start state (CDN URL arrives first; AES key comes second)
    std::mutex              aes_mu_;
    uint32_t                aes_seq_        = 0;
    std::string             pending_cdn_url_;
    std::vector<uint8_t>    pending_file_id_;
    int                     pending_pos_ms_ = 0;

    // Serialises credential processing -- drops duplicate addUser pushes that
    // arrive while we're mid-handshake (Spotify app often retries quickly).
    std::mutex          connect_mu_;
    // pthread so we can set a large stack (AP TLS handshake overflows std::thread default).
    pthread_t           connect_pth_ = 0;
    // Set true in on_credentials before ap_->disconnect() so on_disconnect
    // knows not to reset the display (we're about to bring up a new session).
    std::atomic<bool>   reconnecting_{false};
};

} // namespace Connect
