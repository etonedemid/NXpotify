#pragma once
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <vector>
#include <cstdint>

namespace Connect {

// Maintains a WebSocket connection to wss://dealer.spotify.com.
//
// Protocol:
//   connect  →  server sends {"headers":{"Spotify-Connection-Id":"<id>"},...}
//   client   →  send {"type":"ping"} every 25 s to keep the socket alive
//   server   →  replies {"type":"pong"} and cluster-update messages
//   server   →  sends {"type":"request",...} for player commands (play/pause/seek/…)

class Dealer {
public:
    // Called once (from the Dealer thread) when the connection_id is available.
    using ConnIdCallback = std::function<void(const std::string &connection_id)>;

    // Called for every incoming subscription message (from the Dealer thread).
    // uri     — the hm:// URI from the JSON "uri" field
    // payload — base64-decoded first element of the JSON "payloads" array
    using MessageCallback = std::function<void(const std::string &uri,
                                               const std::vector<uint8_t> &payload)>;

    // Called for incoming player-command requests (from the Dealer thread).
    // message_ident — the hm:// URI identifying the command routing
    // cmd_json      — decoded JSON string with "endpoint", "message_id", etc.
    // Return true to reply {"success":true}, false for {"success":false}.
    using RequestCallback = std::function<bool(const std::string &message_ident,
                                               const std::string &cmd_json)>;

    Dealer() = default;
    ~Dealer();

    // Start the WebSocket connection.  ws_url is the complete wss:// URL
    // (including ?access_token=…).  on_conn_id fires when the server delivers
    // its Spotify-Connection-Id.  on_message fires for subscription events.
    // on_request fires for player-command requests and must return success/failure.
    void start(const std::string &ws_url, ConnIdCallback on_conn_id,
               MessageCallback on_message = nullptr,
               RequestCallback on_request = nullptr);
    void stop();

private:
    void run(std::string ws_url, ConnIdCallback conn_cb,
             MessageCallback msg_cb, RequestCallback req_cb);

    std::atomic<bool> stop_{false};
    std::thread       thread_;
};

} // namespace Connect
