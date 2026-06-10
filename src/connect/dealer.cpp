#include "dealer.h"

#include <curl/curl.h>
#include <curl/websockets.h>
#include <whb/log.h>
#include <coreinit/thread.h>
#include <zlib.h>

#include <cstring>
#include <ctime>

namespace Connect {

// Extract the value for a JSON string key anywhere in a flat JSON document.
static std::string json_str(const std::string &json, const char *key) {
    std::string needle = std::string("\"") + key + "\":\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    std::string out;
    for (; pos < json.size(); ++pos) {
        char c = json[pos];
        if (c == '"') break;
        if (c == '\\' && pos + 1 < json.size()) { out += json[++pos]; }
        else                                      { out += c; }
    }
    return out;
}

// Extract the first string element from a JSON array: "key":["value",...].
static std::string json_array_first(const std::string &json, const char *key) {
    std::string needle = std::string("\"") + key + "\":[\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    std::string out;
    for (; pos < json.size(); ++pos) {
        char c = json[pos];
        if (c == '"') break;
        if (c == '\\' && pos + 1 < json.size()) { out += json[++pos]; }
        else                                      { out += c; }
    }
    return out;
}

// Bracket-balance scan starting at json[start] (which must be '{').
// Skips JSON string contents so braces inside strings are ignored.
// Returns the substring from start to the matching '}'.
static std::string brace_extract(const std::string &json, size_t start) {
    int depth = 0;
    bool in_str = false;
    for (size_t i = start; i < json.size(); ++i) {
        char c = json[i];
        if (in_str) {
            if (c == '\\') { ++i; continue; }
            if (c == '"')  in_str = false;
        } else {
            if      (c == '"') in_str = true;
            else if (c == '{') ++depth;
            else if (c == '}') { if (--depth == 0) return json.substr(start, i - start + 1); }
        }
    }
    return {};
}

// Extract the first object element from a JSON array: "key":[{...},...].
// Returns the matched object as a raw JSON substring.
static std::string json_array_first_obj(const std::string &json, const char *key) {
    std::string needle = std::string("\"") + key + "\":[{";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    return brace_extract(json, pos + needle.size() - 1);
}

// Extract a nested JSON object value by key: "key":{...}.
// Returns the matched object as a raw JSON substring.
static std::string json_extract_obj(const std::string &json, const char *key) {
    std::string needle = std::string("\"") + key + "\":{";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    return brace_extract(json, pos + needle.size() - 1);
}

static std::vector<uint8_t> gunzip(const std::vector<uint8_t> &in) {
    z_stream z = {};
    if (inflateInit2(&z, 16 + MAX_WBITS) != Z_OK) return {};
    z.avail_in = (uInt)in.size();
    z.next_in  = (Bytef *)in.data();
    std::vector<uint8_t> out;
    uint8_t buf[4096];
    int ret;
    do {
        z.avail_out = sizeof(buf);
        z.next_out  = buf;
        ret = inflate(&z, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&z); return {};
        }
        out.insert(out.end(), buf, buf + sizeof(buf) - z.avail_out);
    } while (z.avail_out == 0);
    inflateEnd(&z);
    return out;
}

static std::vector<uint8_t> base64_decode(const std::string &s) {
    static const int8_t T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    int val = 0, bits = 0;
    for (unsigned char c : s) {
        int v = T[c];
        if (v < 0) continue;
        val = (val << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((uint8_t)(val >> bits)); val &= (1 << bits) - 1; }
    }
    return out;
}

// ── Dealer ────────────────────────────────────────────────────────────────────

Dealer::~Dealer() { stop(); }

void Dealer::start(const std::string &ws_url, ConnIdCallback conn_cb,
                   MessageCallback msg_cb, RequestCallback req_cb) {
    stop_.store(false);
    thread_ = std::thread([this, ws_url,
                           conn_cb = std::move(conn_cb),
                           msg_cb  = std::move(msg_cb),
                           req_cb  = std::move(req_cb)]() mutable {
        run(ws_url, std::move(conn_cb), std::move(msg_cb), std::move(req_cb));
    });
}

void Dealer::stop() {
    stop_.store(true);
    if (thread_.joinable()) thread_.join();
}

void Dealer::run(std::string ws_url, ConnIdCallback conn_cb,
                 MessageCallback msg_cb, RequestCallback req_cb) {
    OSSetThreadAffinity(OSGetCurrentThread(), OS_THREAD_ATTRIB_AFFINITY_CPU0);
    if (stop_.load()) return;

    std::string url = ws_url;

    CURL *curl = curl_easy_init();
    if (!curl) { WHBLogPrint("dealer: curl_easy_init failed"); return; }

    curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY,   2L);   // WebSocket upgrade mode
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        0L);   // no total-time limit

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        WHBLogPrintf("dealer: connect failed: %s", curl_easy_strerror(rc));
        curl_easy_cleanup(curl);
        return;
    }
    WHBLogPrint("dealer: WebSocket connected");

    bool        got_cid = false;
    time_t      last_ping = time(nullptr);
    std::string frame_buf;
    // Cap per-message accumulation at 512 KB to prevent runaway growth on
    // corrupted or dead connections.
    static constexpr size_t kMaxFrameBytes = 512 * 1024;

    while (!stop_.load()) {
        // Ping every 25 s — Spotify closes idle Dealer connections after ~30 s
        time_t now = time(nullptr);
        if (now - last_ping >= 25) {
            const char *ping = "{\"type\":\"ping\"}";
            size_t sent = 0;
            rc = curl_ws_send(curl, ping, strlen(ping), &sent, 0, CURLWS_TEXT);
            if (rc == CURLE_OK) {
                last_ping = now;
            } else {
                WHBLogPrintf("dealer: ping failed rc=%d", (int)rc);
                break;
            }
        }

        uint8_t buf[16384];
        size_t  recvd = 0;
        const struct curl_ws_frame *meta = nullptr;

        rc = curl_ws_recv(curl, buf, sizeof(buf), &recvd, &meta);

        if (rc == CURLE_AGAIN) {
            OSSleepTicks(OSMillisecondsToTicks(50));
            continue;
        }
        if (rc != CURLE_OK) {
            WHBLogPrintf("dealer: recv error rc=%d", (int)rc);
            break;
        }
        if (recvd == 0) continue;

        frame_buf.append(reinterpret_cast<char *>(buf), recvd);

        // libcurl-declared continuation: more WS fragments or partial frame.
        if (meta && ((meta->flags & CURLWS_CONT) || meta->bytesleft > 0)) continue;

        // Extra guard: some libcurl ports mis-report partial frame delivery as
        // complete.  If the accumulated buffer looks like an unbalanced JSON
        // object, keep reading until it closes or we hit the size cap.
        if (frame_buf.size() < kMaxFrameBytes &&
                !frame_buf.empty() && frame_buf[0] == '{') {
            int  depth  = 0;
            bool in_str = false;
            bool closed = false;
            for (size_t i = 0; i < frame_buf.size(); i++) {
                char c = frame_buf[i];
                if (in_str) {
                    if (c == '\\') { i++; continue; }
                    if (c == '"') in_str = false;
                } else {
                    if      (c == '"') in_str = true;
                    else if (c == '{') ++depth;
                    else if (c == '}') { if (--depth == 0) { closed = true; break; } }
                }
            }
            if (!closed) continue;
        }

        std::string msg = std::move(frame_buf);
        frame_buf.clear();

        // Handle server-initiated PING: reply with pong text (Spotify convention)
        if (meta && (meta->flags & CURLWS_PING)) {
            const char *pong = "{\"type\":\"pong\"}";
            size_t sent = 0;
            curl_ws_send(curl, pong, strlen(pong), &sent, 0, CURLWS_TEXT);
            continue;
        }

        // Ignore non-text frames (binary, close handled below)
        if (meta && (meta->flags & CURLWS_CLOSE)) {
            WHBLogPrint("dealer: server closed connection");
            break;
        }

        if (!got_cid) {
            std::string cid = json_str(msg, "Spotify-Connection-Id");
            if (!cid.empty()) {
                WHBLogPrintf("dealer: connection_id(%zu chars)", cid.size());
                got_cid = true;
                if (conn_cb) conn_cb(cid);
            }
        }

        std::string msg_type = json_str(msg, "type");

        // New-style player command (modern Spotify desktop/mobile):
        // {"message_ident":"hm://...","payload":{"message_id":N,...,"command":{...}}}
        // No "type" field; payload is a singular JSON object, not an array.
        std::string ident = json_str(msg, "message_ident");
        if (msg_type.empty() && !ident.empty()) {
            if (req_cb) {
                std::string payload = json_extract_obj(msg, "payload");
                if (!payload.empty()) {
                    WHBLogPrintf("dealer: cmd-ident=%.60s", ident.c_str());
                    req_cb(ident, payload);
                } else {
                    WHBLogPrintf("dealer: message_ident no payload obj sz=%zu", msg.size());
                }
            }
        } else if (msg_type == "request") {
            // Player command request — dispatch payload, then send reply keyed by "key".
            std::string key   = json_str(msg, "key");
            std::string b64   = json_str(msg, "compressed");
            std::string tenc  = json_str(msg, "Transfer-Encoding");

            bool ok = false;
            if (req_cb) {
                if (!b64.empty()) {
                    // Legacy: payload is base64+gzip compressed JSON.
                    auto raw = base64_decode(b64);
                    if (tenc == "gzip") raw = gunzip(raw);
                    if (!raw.empty()) {
                        std::string cmd(raw.begin(), raw.end());
                        WHBLogPrintf("dealer: request-gz ident=%.50s", ident.c_str());
                        ok = req_cb(ident, cmd);
                    }
                } else {
                    // Modern: payload is an embedded JSON object ("payload":{...}).
                    std::string payload = json_extract_obj(msg, "payload");
                    if (!payload.empty()) {
                        WHBLogPrintf("dealer: request-obj ident=%.50s", ident.c_str());
                        ok = req_cb(ident, payload);
                    } else {
                        WHBLogPrintf("dealer: request no payload sz=%zu", msg.size());
                    }
                }
            }

            if (!key.empty()) {
                std::string reply = std::string("{\"type\":\"reply\",\"key\":\"") + key +
                                    "\",\"payload\":{\"success\":" +
                                    (ok ? "true" : "false") + "}}";
                size_t sent = 0;
                CURLcode rrc = curl_ws_send(curl, reply.c_str(), reply.size(),
                                            &sent, 0, CURLWS_TEXT);
                if (rrc != CURLE_OK)
                    WHBLogPrintf("dealer: reply send failed rc=%d", (int)rrc);
            }
        } else {
            // Subscription message — dispatch by URI.
            std::string uri = json_str(msg, "uri");
            if (!uri.empty()) {
                WHBLogPrintf("dealer: msg uri='%.80s'", uri.c_str());
                std::string b64 = json_array_first(msg, "payloads");
                if (!b64.empty()) {
                    // Base64-encoded binary payload (ClusterUpdate, etc.)
                    if (msg_cb) msg_cb(uri, base64_decode(b64));
                } else if (req_cb) {
                    std::string obj = json_array_first_obj(msg, "payloads");
                    if (!obj.empty()) {
                        WHBLogPrintf("dealer: cmd-msg ident=%.60s", uri.c_str());
                        req_cb(uri, obj);
                    }
                }
            }
        }
    }

    curl_easy_cleanup(curl);
    WHBLogPrint("dealer: disconnected");
}

} // namespace Connect
