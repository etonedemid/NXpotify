#include "dealer.h"
#include "platform.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/base64.h>

#include <zlib.h>

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <poll.h>

namespace Connect {

// ── JSON helpers ──────────────────────────────────────────────────────────────

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

static std::string json_array_first_obj(const std::string &json, const char *key) {
    std::string needle = std::string("\"") + key + "\":[{";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    return brace_extract(json, pos + needle.size() - 1);
}

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

// ── WebSocket client (mbedTLS 2.28, TLS 1.2) ─────────────────────────────────

// WebSocket opcodes
enum : uint8_t { WS_CONT=0, WS_TEXT=1, WS_BINARY=2, WS_CLOSE=8, WS_PING=9, WS_PONG=10 };

struct WsConn {
    mbedtls_net_context      net{};
    mbedtls_entropy_context  entropy{};
    mbedtls_ctr_drbg_context drbg{};
    mbedtls_ssl_context      ssl{};
    mbedtls_ssl_config       conf{};
    bool valid = false;

    WsConn() {
        mbedtls_net_init(&net);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
    }
    ~WsConn() {
        if (valid) mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
        mbedtls_net_free(&net);
    }
    WsConn(const WsConn&) = delete;
    WsConn& operator=(const WsConn&) = delete;
};

// Parse wss://host[:port]/path?query → host, port_str, path_and_query
static bool parse_wss(const std::string &url,
                      std::string &host, std::string &port_str, std::string &path) {
    if (url.size() < 6 || url.substr(0, 6) != "wss://") return false;
    size_t a = 6;
    size_t sl = url.find('/', a);
    std::string auth = (sl == std::string::npos) ? url.substr(a) : url.substr(a, sl - a);
    path = (sl == std::string::npos) ? "/" : url.substr(sl);
    size_t col = auth.rfind(':');
    if (col != std::string::npos) {
        host     = auth.substr(0, col);
        port_str = auth.substr(col + 1);
    } else {
        host     = auth;
        port_str = "443";
    }
    return !host.empty();
}

// Establish TLS 1.2 connection via mbedTLS 2.28.
// Sets read timeout to 1 s so ws_recv_frame() can be interruptible.
static bool ssl_connect(WsConn &ws, const char *host, const char *port) {
    mbedtls_ctr_drbg_seed(&ws.drbg, mbedtls_entropy_func, &ws.entropy,
                           (const uint8_t *)"dealer", 6);
    if (mbedtls_net_connect(&ws.net, host, port, MBEDTLS_NET_PROTO_TCP) != 0) {
        PLAT_LOG("dealer: TCP connect failed");
        return false;
    }
    mbedtls_ssl_config_defaults(&ws.conf,
                                 MBEDTLS_SSL_IS_CLIENT,
                                 MBEDTLS_SSL_TRANSPORT_STREAM,
                                 MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&ws.conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&ws.conf, mbedtls_ctr_drbg_random, &ws.drbg);
    mbedtls_ssl_conf_read_timeout(&ws.conf, 1000);  // 1 s: allows ping checks in loop

    mbedtls_ssl_setup(&ws.ssl, &ws.conf);
    mbedtls_ssl_set_hostname(&ws.ssl, host);
    mbedtls_ssl_set_bio(&ws.ssl, &ws.net,
                         mbedtls_net_send, nullptr, mbedtls_net_recv_timeout);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&ws.ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            PLAT_LOGF("dealer: TLS handshake failed: -0x%04X", (unsigned)(-ret));
            return false;
        }
    }
    ws.valid = true;
    PLAT_LOG("dealer: TLS connected");
    return true;
}

// Read exactly len bytes from TLS, blocking with per-call 1 s timeout.
// Returns false on connection error or stop.
static bool ssl_read_exact(WsConn &ws, uint8_t *buf, size_t len,
                            const std::atomic<bool> &stop) {
    while (len > 0) {
        if (stop.load()) return false;
        int ret = mbedtls_ssl_read(&ws.ssl, buf, len);
        if (ret == MBEDTLS_ERR_SSL_TIMEOUT || ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
        if (ret <= 0) return false;
        buf += ret; len -= (size_t)ret;
    }
    return true;
}

// Write all bytes to TLS.
static bool ssl_write_all(WsConn &ws, const uint8_t *buf, size_t len) {
    while (len > 0) {
        int ret = mbedtls_ssl_write(&ws.ssl, buf, len);
        if (ret <= 0) return false;
        buf += ret; len -= (size_t)ret;
    }
    return true;
}

// Send HTTP Upgrade and consume the 101 response.
static bool http_upgrade(WsConn &ws, const std::string &host, const std::string &path,
                          const std::atomic<bool> &stop) {
    // Build a random Sec-WebSocket-Key (16 random bytes → base64)
    srand((unsigned)time(nullptr));
    uint8_t raw_key[16];
    for (auto &b : raw_key) b = (uint8_t)rand();
    size_t olen = 0;
    mbedtls_base64_encode(nullptr, 0, &olen, raw_key, 16);
    std::string ws_key(olen, '\0');
    mbedtls_base64_encode((uint8_t *)ws_key.data(), olen, &olen, raw_key, 16);
    ws_key.resize(olen);

    std::string req =
        "GET " + path + " HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: " + ws_key + "\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n";
    if (!ssl_write_all(ws, (const uint8_t *)req.data(), req.size())) {
        PLAT_LOG("dealer: upgrade send failed");
        return false;
    }

    // Read response headers until \r\n\r\n
    std::string resp;
    resp.reserve(512);
    uint8_t ch;
    while (resp.size() < 8192) {
        if (!ssl_read_exact(ws, &ch, 1, stop)) { PLAT_LOG("dealer: upgrade recv failed"); return false; }
        resp += (char)ch;
        if (resp.size() >= 4 && resp.compare(resp.size() - 4, 4, "\r\n\r\n") == 0) break;
    }
    if (resp.find("101") == std::string::npos) {
        PLAT_LOGF("dealer: upgrade rejected: %.120s", resp.c_str());
        return false;
    }
    PLAT_LOG("dealer: WebSocket connected");
    return true;
}

// Send a WebSocket text frame (RFC 6455, client masking required).
static bool ws_send(WsConn &ws, uint8_t opcode, const void *data, size_t len) {
    uint8_t hdr[14];
    size_t hdr_len = 0;
    hdr[hdr_len++] = 0x80 | opcode;  // FIN=1

    uint8_t mask[4] = { (uint8_t)rand(), (uint8_t)rand(),
                        (uint8_t)rand(), (uint8_t)rand() };
    if (len <= 125) {
        hdr[hdr_len++] = 0x80 | (uint8_t)len;
    } else if (len <= 65535) {
        hdr[hdr_len++] = 0x80 | 126;
        hdr[hdr_len++] = (uint8_t)(len >> 8);
        hdr[hdr_len++] = (uint8_t)(len & 0xFF);
    } else {
        hdr[hdr_len++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) hdr[hdr_len++] = (uint8_t)((len >> (i * 8)) & 0xFF);
    }
    memcpy(hdr + hdr_len, mask, 4);
    hdr_len += 4;

    // Combine header + masked payload in one write buffer
    std::vector<uint8_t> frame(hdr_len + len);
    memcpy(frame.data(), hdr, hdr_len);
    auto *src = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) frame[hdr_len + i] = src[i] ^ mask[i % 4];

    return ssl_write_all(ws, frame.data(), frame.size());
}

static bool ws_send_text(WsConn &ws, const std::string &text) {
    return ws_send(ws, WS_TEXT, text.data(), text.size());
}
static bool ws_send_pong(WsConn &ws, const std::string &body) {
    return ws_send(ws, WS_PONG, body.data(), body.size());
}

// Receive one WebSocket frame.
// Returns: 1=ok, 0=timeout (no data in 1 s), -1=error or close
// Accumulates fragmented messages in frame_buf; opcode=0 means "still fragmenting".
static int ws_recv_frame(WsConn &ws, uint8_t &out_opcode, std::string &out_payload,
                         const std::atomic<bool> &stop) {
    // First byte of header: try with 1-second TLS timeout
    uint8_t b0;
    {
        int ret = mbedtls_ssl_read(&ws.ssl, &b0, 1);
        if (ret == MBEDTLS_ERR_SSL_TIMEOUT || ret == MBEDTLS_ERR_SSL_WANT_READ) return 0;
        if (ret <= 0) return -1;
    }
    // Second byte: we already started, block until received
    uint8_t b1;
    if (!ssl_read_exact(ws, &b1, 1, stop)) return -1;

    bool fin    = (b0 & 0x80) != 0;
    uint8_t op  = (b0 & 0x0F);
    bool masked = (b1 & 0x80) != 0;
    uint64_t plen = (b1 & 0x7F);

    if (plen == 126) {
        uint8_t ext[2];
        if (!ssl_read_exact(ws, ext, 2, stop)) return -1;
        plen = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (plen == 127) {
        uint8_t ext[8];
        if (!ssl_read_exact(ws, ext, 8, stop)) return -1;
        plen = 0;
        for (int i = 0; i < 8; i++) plen = (plen << 8) | ext[i];
    }

    uint8_t mask[4] = {};
    if (masked) {
        if (!ssl_read_exact(ws, mask, 4, stop)) return -1;
    }

    // Read payload
    std::string payload(plen, '\0');
    if (!ssl_read_exact(ws, (uint8_t *)payload.data(), plen, stop)) return -1;
    if (masked) {
        for (size_t i = 0; i < plen; i++) payload[i] ^= mask[i % 4];
    }

    out_opcode  = op;
    out_payload = std::move(payload);
    (void)fin;
    return 1;
}

// ── Dealer ────────────────────────────────────────────────────────────────────

Dealer::~Dealer() { stop(); }

void Dealer::start(const std::string &ws_url, ConnIdCallback conn_cb,
                   MessageCallback msg_cb, RequestCallback req_cb) {
    stop_.store(false);
    struct Arg { Dealer *self; std::string ws_url; ConnIdCallback conn_cb; MessageCallback msg_cb; RequestCallback req_cb; };
    auto *arg = new Arg{this, ws_url, std::move(conn_cb), std::move(msg_cb), std::move(req_cb)};
    pthread_attr_t attr; pthread_attr_init(&attr); pthread_attr_setstacksize(&attr, 1024*1024);
    pthread_create(&thread_, &attr, [](void *vp) -> void* {
        auto *a = static_cast<Arg*>(vp);
        a->self->run(std::move(a->ws_url), std::move(a->conn_cb), std::move(a->msg_cb), std::move(a->req_cb));
        delete a; return nullptr;
    }, arg);
    pthread_attr_destroy(&attr);
}

void Dealer::stop() {
    stop_.store(true);
    if (thread_) { pthread_join(thread_, nullptr); thread_ = 0; }
}

void Dealer::run(std::string ws_url, ConnIdCallback conn_cb,
                 MessageCallback msg_cb, RequestCallback req_cb) {
    if (stop_.load()) return;

    // Parse wss:// URL
    std::string host, port_str, path;
    if (!parse_wss(ws_url, host, port_str, path)) {
        PLAT_LOGF("dealer: bad URL: %.80s", ws_url.c_str());
        return;
    }

    // TLS connect + WebSocket upgrade
    WsConn ws;
    if (!ssl_connect(ws, host.c_str(), port_str.c_str())) return;
    if (!http_upgrade(ws, host, path, stop_)) return;

    bool        got_cid  = false;
    time_t      last_ping = time(nullptr);
    std::string frame_buf;
    uint8_t     frag_opcode = 0;  // opcode of the fragmented message being assembled
    static constexpr size_t kMaxFrameBytes = 512 * 1024;

    while (!stop_.load()) {
        // Ping every 25 s
        time_t now = time(nullptr);
        if (now - last_ping >= 25) {
            const char *ping_msg = "{\"type\":\"ping\"}";
            if (ws_send_text(ws, ping_msg)) {
                last_ping = now;
            } else {
                PLAT_LOG("dealer: ping failed");
                break;
            }
        }

        uint8_t     opcode  = 0;
        std::string payload;
        int ret = ws_recv_frame(ws, opcode, payload, stop_);
        if (ret == 0) continue;  // timeout: loop, check stop/ping
        if (ret <  0) { PLAT_LOG("dealer: recv error"); break; }

        // Handle control frames (take priority, never fragmented)
        if (opcode == WS_PING) {
            ws_send_pong(ws, payload);
            continue;
        }
        if (opcode == WS_CLOSE) {
            PLAT_LOG("dealer: server closed connection");
            break;
        }
        if (opcode == WS_PONG) continue;

        // Data frame -- assemble fragmented messages
        if (opcode == WS_TEXT || opcode == WS_BINARY) {
            frag_opcode = opcode;
            frame_buf   = std::move(payload);
        } else if (opcode == WS_CONT) {
            frame_buf += payload;
        }

        // If still fragmenting, check if JSON is closed or if we hit size cap
        if (frame_buf.size() < kMaxFrameBytes &&
                !frame_buf.empty() && frame_buf[0] == '{') {
            int depth = 0; bool in_str = false; bool closed = false;
            for (size_t i = 0; i < frame_buf.size(); i++) {
                char c = frame_buf[i];
                if (in_str) {
                    if (c == '\\') { i++; continue; }
                    if (c == '"') in_str = false;
                } else {
                    if (c == '"') in_str = true;
                    else if (c == '{') ++depth;
                    else if (c == '}') { if (--depth == 0) { closed = true; break; } }
                }
            }
            if (!closed) continue;
        }
        if (frame_buf.size() >= kMaxFrameBytes) {
            PLAT_LOGF("dealer: frame too large (%zu bytes), discarding", frame_buf.size());
            frame_buf.clear();
            continue;
        }

        std::string msg = std::move(frame_buf);
        frame_buf.clear();
        frag_opcode = 0;

        // Deliver connection_id
        if (!got_cid) {
            std::string cid = json_str(msg, "Spotify-Connection-Id");
            if (!cid.empty()) {
                PLAT_LOGF("dealer: connection_id(%zu chars)", cid.size());
                got_cid = true;
                if (conn_cb) conn_cb(cid);
            }
        }

        std::string msg_type = json_str(msg, "type");
        std::string ident    = json_str(msg, "message_ident");

        if (msg_type.empty() && !ident.empty()) {
            // New-style player command
            if (req_cb) {
                std::string pload = json_extract_obj(msg, "payload");
                if (!pload.empty()) {
                    PLAT_LOGF("dealer: cmd-ident=%.60s", ident.c_str());
                    req_cb(ident, pload);
                } else {
                    PLAT_LOGF("dealer: message_ident no payload sz=%zu", msg.size());
                }
            }
        } else if (msg_type == "request") {
            std::string key   = json_str(msg, "key");
            std::string b64   = json_str(msg, "compressed");
            std::string tenc  = json_str(msg, "Transfer-Encoding");

            bool ok = false;
            if (req_cb) {
                if (!b64.empty()) {
                    auto raw = base64_decode(b64);
                    if (tenc == "gzip") raw = gunzip(raw);
                    if (!raw.empty()) {
                        std::string cmd(raw.begin(), raw.end());
                        PLAT_LOGF("dealer: request-gz ident=%.50s", ident.c_str());
                        ok = req_cb(ident, cmd);
                    }
                } else {
                    std::string pload = json_extract_obj(msg, "payload");
                    if (!pload.empty()) {
                        PLAT_LOGF("dealer: request-obj ident=%.50s", ident.c_str());
                        ok = req_cb(ident, pload);
                    } else {
                        PLAT_LOGF("dealer: request no payload sz=%zu", msg.size());
                    }
                }
            }
            if (!key.empty()) {
                std::string reply =
                    std::string("{\"type\":\"reply\",\"key\":\"") + key +
                    "\",\"payload\":{\"success\":" + (ok ? "true" : "false") + "}}";
                if (!ws_send_text(ws, reply))
                    PLAT_LOG("dealer: reply send failed");
            }
        } else {
            // Subscription message
            std::string uri = json_str(msg, "uri");
            if (!uri.empty()) {
                PLAT_LOGF("dealer: msg uri='%.80s'", uri.c_str());
                std::string b64 = json_array_first(msg, "payloads");
                if (!b64.empty()) {
                    if (msg_cb) msg_cb(uri, base64_decode(b64));
                } else if (req_cb) {
                    std::string obj = json_array_first_obj(msg, "payloads");
                    if (!obj.empty()) {
                        PLAT_LOGF("dealer: cmd-msg ident=%.60s", uri.c_str());
                        req_cb(uri, obj);
                    }
                }
            }
        }
    }

    PLAT_LOG("dealer: disconnected");
}

} // namespace Connect
