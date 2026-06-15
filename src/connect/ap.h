#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <pthread.h>
#include <atomic>
#include <mutex>
#include <memory>
#include "../discovery/zeroconf.h"
#include <memory>
#include <curl/curl.h>

namespace Connect {

class Shannon;

// ── Command codes ─────────────────────────────────────────────────────────────
namespace Cmd {
    constexpr uint8_t SecretBlock  = 0x02;
    constexpr uint8_t Ping         = 0x04;
    constexpr uint8_t StreamChunk  = 0x08;
    constexpr uint8_t StreamChunkRes = 0x09;
    constexpr uint8_t ChannelError = 0x0A;
    constexpr uint8_t ChannelAbort = 0x0B;
    constexpr uint8_t RequestKey   = 0x0C;
    constexpr uint8_t AesKey       = 0x0D;
    constexpr uint8_t AesKeyError  = 0x0E;
    constexpr uint8_t Image        = 0x19;
    constexpr uint8_t CountryCode  = 0x1B;
    constexpr uint8_t Pong         = 0x49;
    constexpr uint8_t PongAck      = 0x4A;
    constexpr uint8_t Pause        = 0x4B;
    constexpr uint8_t ProductInfo  = 0x50;
    constexpr uint8_t LegacyWelcome = 0x69;
    constexpr uint8_t LicenseVersion = 0x76;
    constexpr uint8_t Login        = 0xAB;
    constexpr uint8_t APWelcome    = 0xAC;
    constexpr uint8_t AuthFailure  = 0xAD;
    constexpr uint8_t MercuryReq   = 0xB2;
    constexpr uint8_t MercurySub   = 0xB3;
    constexpr uint8_t MercuryUnsub = 0xB4;
    constexpr uint8_t MercuryEvent = 0xB5;
    constexpr uint8_t MercuryAck   = 0xB6;
}

// ── AP layer ──────────────────────────────────────────────────────────────────
//
// Handles the Spotify Access Point binary protocol:
//   1. Resolves the AP address via https://apresolve.spotify.com/
//   2. TCP connect → Shannon-secured handshake (DH key exchange)
//   3. Login with stored Zeroconf credentials
//   4. Background receive loop -- dispatches packets to on_packet
//
// Thread safety:
//   send_packet() is safe to call from any thread (guarded by send_mu_).
//   on_packet / on_disconnect are invoked from the recv thread.

class AP {
public:
    struct Callbacks {
        // Called for every packet the AP sends us (after login).
        // Invoked from the receive thread -- do not call send_packet() from here
        // without a separate dispatch (deadlock risk if send_mu_ is involved in
        // the callback chain).  Ping is handled internally and not forwarded.
        std::function<void(uint8_t cmd, std::vector<uint8_t> payload)> on_packet;

        // Called when the socket closes or a MAC verification fails.
        std::function<void()> on_disconnect;
    };

    AP();
    ~AP();

    // Connect, handshake, and login.  Blocks until APWelcome (success) or
    // failure.  Returns false on any error.
    bool connect(const Discovery::Credentials &creds, Callbacks cb);

    // Graceful teardown -- signals recv thread to stop and joins.
    void disconnect();

    // Send an encrypted AP packet.  Thread-safe.  Returns false on send failure.
    bool send_packet(uint8_t cmd, const uint8_t *payload, size_t len);
    bool send_packet(uint8_t cmd, const std::vector<uint8_t> &payload);

    bool        is_connected()    const { return connected_.load(); }
    std::string country_code()    const { return country_code_; }
    std::string canonical_username() const { return username_; }
    std::vector<uint8_t> reusable_creds() const { return reusable_creds_; }

private:
    // ── connection setup ──────────────────────────────────────────────────────
    bool resolve_ap(std::vector<std::pair<std::string,uint16_t>> &aps);
    bool tcp_connect(const std::string &host, uint16_t port);
    bool do_handshake();
    bool do_login(const Discovery::Credentials &creds);

    // ── wire I/O ──────────────────────────────────────────────────────────────
    bool send_raw(const uint8_t *buf, size_t len);
    bool recv_exact(uint8_t *buf, size_t n);

    // Send length-prefixed plain message (handshake phase)
    bool send_plain(const std::vector<uint8_t> &msg);
    // Recv length-prefixed plain message; raw bytes (incl. prefix) stored in out_raw
    bool recv_plain(std::vector<uint8_t> &msg, std::vector<uint8_t> &raw);

    // ── receive loop ──────────────────────────────────────────────────────────
    void recv_loop();

    // ── socket ───────────────────────────────────────────────────────────────
    int fd_ = -1;

    // ── curl handle ──────────────────────────────────────────────────────────
    // curl CONNECT_ONLY is used to establish the TCP connection (the Wii U's
    // raw connect() is unreliable for outbound TCP).  After do_handshake()
    // completes, raw_recv_ is set true and recv_exact switches to blocking
    // POSIX recv() -- curl's internal state appears to swallow incoming data
    // after the handshake phase, preventing POLLIN from ever firing.
    CURL *curl_       = nullptr;
    bool  raw_recv_   = false;  // true after handshake: bypass curl for recv

    // ── Shannon ciphers (set up after handshake) ──────────────────────────────
    std::unique_ptr<Shannon> send_cipher_;
    std::unique_ptr<Shannon> recv_cipher_;
    uint32_t send_seq_ = 0;
    uint32_t recv_seq_ = 0;

    std::mutex   send_mu_;
    pthread_t    recv_thread_ = 0;
    std::atomic<bool> stop_     {false};
    std::atomic<bool> connected_{false};

    Callbacks    callbacks_;
    std::string  country_code_;
    std::string  username_;         // canonical username from APWelcome
    std::vector<uint8_t> reusable_creds_;  // 20-byte reusable credential from APWelcome
};

} // namespace Connect
