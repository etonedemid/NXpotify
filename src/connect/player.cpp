#include "player.h"
#include "ap.h"
#include "spirc.h"
#include "audio.h"

#include <cstdio>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <mutex>
#include <thread>
#include <pthread.h>

#include <switch.h>
#include <curl/curl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

extern "C" {
#include "cJSON/cJSON.h"
}

#include "platform.h"

namespace Connect {

// ── HTTP helpers used by device_auth() ───────────────────────────────────────

static size_t da_write_str(char *ptr, size_t sz, size_t n, void *ud) {
    reinterpret_cast<std::string *>(ud)->append(ptr, sz * n);
    return sz * n;
}

static size_t da_write_vec(char *ptr, size_t sz, size_t n, void *ud) {
    auto *v = reinterpret_cast<std::vector<uint8_t> *>(ud);
    v->insert(v->end(), reinterpret_cast<uint8_t *>(ptr),
              reinterpret_cast<uint8_t *>(ptr) + sz * n);
    return sz * n;
}

static std::string da_post(const char *url, const std::string &body) {
    std::string resp;
    CURL *c = curl_easy_init();
    if (!c) return resp;
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body.size());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, da_write_str);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(c, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 1L);
    // Prevent curl from adding Accept-Encoding which yields compressed responses
    curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");
    CURLcode rc = curl_easy_perform(c);
    curl_easy_cleanup(c);
    PLAT_LOGF("da_post: rc=%d resp_len=%zu", (int)rc, resp.size());
    return resp;
}

static std::vector<uint8_t> da_get_bytes(const std::string &url) {
    std::vector<uint8_t> data;
    CURL *c = curl_easy_init();
    if (!c) return data;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, da_write_vec);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    curl_easy_perform(c);
    curl_easy_cleanup(c);
    return data;
}

static std::string da_urlencode(const std::string &s) {
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += (char)c;
        } else {
            char buf[4];
            snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string make_device_id() {
    auto *entropy  = new mbedtls_entropy_context;
    auto *ctr_drbg = new mbedtls_ctr_drbg_context;
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                          reinterpret_cast<const uint8_t *>("dev"), 3);
    uint8_t raw[20];
    mbedtls_ctr_drbg_random(ctr_drbg, raw, sizeof(raw));
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    delete ctr_drbg; delete entropy;

    static const char hx[] = "0123456789abcdef";
    std::string s; s.reserve(40);
    for (uint8_t b : raw) { s += hx[b >> 4]; s += hx[b & 0xF]; }
    return s;
}

// ── Constructor / destructor ──────────────────────────────────────────────────

Player::Player()
    : zeroconf_("Switch", make_device_id()),
      ap_(std::make_unique<AP>()),
      audio_(std::make_unique<AudioPipeline>())
{}

Player::~Player() {
    if (spirc_) spirc_->stop();
    if (ap_)    ap_->disconnect();
}

// ── Main loop ─────────────────────────────────────────────────────────────────

void Player::run() {
    // Font is optional -- loaded from SD card if present; nullptr = use embedded fallback.
    static char font_path_buf[256];
    snprintf(font_path_buf, sizeof(font_path_buf),
             "%s/switch/nxpotify/font.ttf", SD_ROOT);
    const char *font_path = nullptr;
    if (FILE *f = fopen(font_path_buf, "rb")) { fclose(f); font_path = font_path_buf; }

    // Switch pad init
    PadState pad;
    padConfigureInput(1, HidNpadStyleTag_NpadFullKey);
    padInitializeDefault(&pad);

    PLAT_LOG("player: init display");
    if (!display_.init(font_path))
        PLAT_LOG("player: display init failed");
    PLAT_LOG("player: display OK");
    display_.set_audio(audio_.get());
    display_.set_waiting();

    PLAT_LOG("player: init audio");
    if (!audio_->init())
        PLAT_LOG("player: audio init failed");
    PLAT_LOG("player: audio OK");

    audio_->on_track_end = [this] {
        spirc_playing_ = false;
        if (spirc_) {
            if (spirc_->repeat_track())
                spirc_->replay_current();
            else
                spirc_->skip(true);
        }
        state_.store(State::Ready);
    };

    // CDN fetch failed (not aborted by stop()) -- reset without telling Spotify the
    // track ended (that would cause it to auto-resend and loop indefinitely).
    audio_->on_fetch_error = [this] {
        PLAT_LOG("player: CDN fetch error -- resetting to waiting");
        spirc_playing_ = false;
        state_.store(State::WaitingForUser);
        display_.set_waiting();
    };

    zeroconf_.start([this](Discovery::Credentials creds) {
        // Detach any prior connect thread before launching a new one.
        if (connect_pth_) { pthread_detach(connect_pth_); connect_pth_ = 0; }
        // Heap-allocate args so they survive until the thread picks them up.
        struct Arg { Player *p; Discovery::Credentials creds; };
        auto *arg = new Arg{this, std::move(creds)};
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 1024 * 1024);  // AP TLS needs large stack
        pthread_create(&connect_pth_, &attr, [](void *vp) -> void* {
            auto *a = static_cast<Arg*>(vp);
            a->p->on_credentials(std::move(a->creds));
            delete a;
            return nullptr;
        }, arg);
        pthread_attr_destroy(&attr);
    }, [this](std::string msg) {
        display_.set_error(std::move(msg));
    });

    // If no saved credentials exist, run the device auth flow in the background.
    // The main loop below keeps rendering frames so the QR screen is live.
    {
        FILE *f = fopen(SD_ROOT "/spotify_saved_creds.bin", "rb");
        if (f) {
            fclose(f);
            PLAT_LOG("player: saved credentials found");
        } else {
            PLAT_LOG("player: no saved credentials -- starting device auth");
            // curl's TLS stack is deep; std::thread default stack is too small.
            // Use pthread directly with 1 MB so curl_easy_perform doesn't overflow.
            pthread_t da_tid;
            pthread_attr_t da_attr;
            pthread_attr_init(&da_attr);
            pthread_attr_setstacksize(&da_attr, 1024 * 1024);
            pthread_create(&da_tid, &da_attr,
                [](void *arg) -> void* {
                    reinterpret_cast<Player*>(arg)->device_auth();
                    return nullptr;
                }, this);
            pthread_attr_destroy(&da_attr);
            pthread_detach(da_tid);
        }
    }

    PLAT_LOG("player: entering main loop");

    uint64_t last_notify_tick = 0;

    while (plat_running()) {
        display_.render();

        padUpdate(&pad);
        display_.set_handheld(padIsHandheld(&pad));
        u64 trigger = padGetButtonsDown(&pad);
        if (trigger)
            handle_buttons((uint32_t)(trigger & 0xFFFFFFFFULL));
        handle_touch();

        // Send position Notify every 1 s so the Spotify app stays in sync.
        if (spirc_playing_) {
            if (audio_->is_playing()) {
                int pos = audio_->position_ms();
                display_.set_progress(pos, track_dur_ms_, true);
            }
            uint64_t now = plat_ticks();
            if (spirc_ && now - last_notify_tick >= plat_s_to_ticks(1)) {
                spirc_->notify(true, audio_->position_ms(), volume_);
                last_notify_tick = now;
            }
        }

        plat_sleep_ms(16);
    }

    // Tell Spotify this device is going away before closing the connection.
    if (spirc_) spirc_->goodbye();

    if (ap_) ap_->disconnect();
    if (connect_pth_) { pthread_join(connect_pth_, nullptr); connect_pth_ = 0; }
    zeroconf_.stop();
    if (spirc_) { spirc_->stop(); spirc_.reset(); }
    audio_->shutdown();
    display_.shutdown();
}

// ── Device Authorization Grant (first-time Spotify login) ────────────────────

static const char *SPOTIFY_CLIENT_ID = "65b708073fc0480ea92a077233ca87bd";
static const char *DEVICE_AUTH_URL   = "https://accounts.spotify.com/oauth2/device/authorize";
static const char *TOKEN_URL         = "https://accounts.spotify.com/api/token";

void Player::device_auth() {
    PLAT_LOG("player: device_auth: requesting device code");
    std::string req_body = std::string("client_id=") + SPOTIFY_CLIENT_ID + "&scope=streaming";
    std::string resp = da_post(DEVICE_AUTH_URL, req_body);
    PLAT_LOGF("player: device_auth: got resp len=%zu", resp.size());
    // Log only safe ASCII portion to avoid binary data going to log
    for (char &ch : resp) if ((unsigned char)ch < 32 || (unsigned char)ch > 126) ch = '?';
    PLAT_LOGF("player: device_auth response: %.300s", resp.c_str());

    cJSON *root = cJSON_Parse(resp.c_str());
    if (!root) {
        PLAT_LOG("player: device_auth: JSON parse failed");
        display_.set_error("Spotify login failed (network error)");
        return;
    }

    const char *device_code = cJSON_GetStringValue(cJSON_GetObjectItem(root, "device_code"));
    const char *user_code   = cJSON_GetStringValue(cJSON_GetObjectItem(root, "user_code"));
    const char *verify_uri  = cJSON_GetStringValue(cJSON_GetObjectItem(root, "verification_uri_complete"));
    cJSON      *iv_item     = cJSON_GetObjectItem(root, "interval");
    cJSON      *ex_item     = cJSON_GetObjectItem(root, "expires_in");

    int poll_interval = iv_item ? (int)cJSON_GetNumberValue(iv_item) : 5;
    int expires_in    = ex_item ? (int)cJSON_GetNumberValue(ex_item) : 300;

    if (!device_code || !user_code || !verify_uri) {
        PLAT_LOG("player: device_auth: missing fields in response");
        cJSON_Delete(root);
        display_.set_error("Spotify login failed (bad response)");
        return;
    }

    PLAT_LOGF("player: device_auth: user_code=%s uri=%.80s", user_code, verify_uri);

    // Fetch QR PNG from quickchart.io
    std::string qr_url = std::string("https://quickchart.io/qr?text=")
                       + da_urlencode(verify_uri) + "&size=300&margin=1&format=png";
    std::vector<uint8_t> qr_png = da_get_bytes(qr_url);
    PLAT_LOGF("player: device_auth: QR PNG %zu bytes", qr_png.size());

    display_.set_login(user_code, qr_png);

    std::string dc(device_code);
    cJSON_Delete(root);

    // Poll token endpoint
    std::string poll_body = std::string("client_id=") + SPOTIFY_CLIENT_ID
        + "&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        + "&device_code=" + da_urlencode(dc);

    for (int elapsed = 0; plat_running() && elapsed < expires_in; elapsed += poll_interval) {
        plat_sleep_ms(poll_interval * 1000);

        std::string token_resp = da_post(TOKEN_URL, poll_body);
        PLAT_LOGF("player: device_auth poll: %.120s", token_resp.c_str());

        cJSON *tr = cJSON_Parse(token_resp.c_str());
        if (!tr) continue;

        const char *err = cJSON_GetStringValue(cJSON_GetObjectItem(tr, "error"));
        if (err) {
            if (strcmp(err, "slow_down") == 0)              poll_interval += 5;
            else if (strcmp(err, "authorization_pending") == 0) { /* keep polling */ }
            else {
                PLAT_LOGF("player: device_auth poll error: %s", err);
                cJSON_Delete(tr);
                display_.set_error("Spotify login cancelled");
                return;
            }
            cJSON_Delete(tr);
            continue;
        }

        const char *access_token = cJSON_GetStringValue(cJSON_GetObjectItem(tr, "access_token"));
        if (access_token) {
            PLAT_LOG("player: device_auth: got access token");
            Discovery::Credentials creds;
            creds.username  = "";          // filled in by AP after login
            creds.device_id = zeroconf_.device_id();
            creds.auth_type = 0x03;        // AUTHENTICATION_SPOTIFY_TOKEN
            creds.auth_data.assign(access_token, access_token + strlen(access_token));
            cJSON_Delete(tr);
            display_.set_waiting();
            on_credentials(std::move(creds));
            return;
        }

        cJSON_Delete(tr);
    }

    PLAT_LOG("player: device_auth: timed out");
    display_.set_error("Spotify login timed out -- restart the app");
}

// ── Credentials -- connect to AP ───────────────────────────────────────────────

void Player::on_credentials(Discovery::Credentials creds) {
    std::unique_lock<std::mutex> lk(connect_mu_, std::try_to_lock);
    if (!lk) {
        PLAT_LOG("player: ignoring duplicate credentials (already connecting)");
        return;
    }
    PLAT_LOGF("player: credentials for '%s'", creds.username.c_str());
    state_.store(State::Connecting);

    if (spirc_) { spirc_->stop(); spirc_.reset(); }
    reconnecting_.store(true);
    if (ap_) ap_->disconnect();
    reconnecting_.store(false);
    ap_ = std::make_unique<AP>();

    uint32_t gen = ++ap_gen_;

    AP::Callbacks acb;
    acb.on_packet     = [this](uint8_t cmd, std::vector<uint8_t> pl) {
        on_ap_packet(cmd, std::move(pl));
    };
    acb.on_disconnect = [this, gen] {
        if (ap_gen_.load() != gen) return;
        PLAT_LOG("player: AP disconnected");
        state_.store(State::WaitingForUser);
        audio_->stop();
        spirc_playing_ = false;
        display_.set_waiting();
        if (!reconnecting_.load() && spirc_)
            spirc_->become_inactive();
    };

    if (!ap_->connect(creds, std::move(acb))) {
        PLAT_LOG("player: AP connect failed");
        state_.store(State::WaitingForUser);
        display_.set_waiting();
        return;
    }

    spirc_ = std::make_unique<Spirc>(ap_.get(),
                                     ap_->canonical_username(),
                                     "Switch",
                                     zeroconf_.device_id());

    Spirc::Callbacks scb;
    scb.on_play = [this](const std::string &uri, int pos) {
        on_play(uri, pos);
    };
    scb.on_file_ready = [this](const std::vector<uint8_t> &fid,
                                const std::vector<uint8_t> &gid,
                                int pos) {
        on_file_ready(fid, gid, pos);
    };
    scb.on_playing_changed = [this](bool playing, int pos_ms) {
        spirc_playing_ = playing;
        if (playing) {
            audio_->resume();
            display_.set_progress(pos_ms, track_dur_ms_, true);
        } else {
            audio_->pause();
            display_.set_progress(audio_->position_ms(), track_dur_ms_, false);
        }
    };
    scb.on_options_changed = [this](bool sh, int rep) {
        display_.set_shuffle(sh);
        display_.set_repeat(rep);
    };
    scb.on_seek         = [this](int pos) { on_seek(pos); };
    scb.on_volume       = [this](int vol) { on_volume(vol); };
    scb.on_became_inactive = [this] {
        audio_->stop();
        spirc_playing_ = false;
        display_.set_waiting();
    };
    scb.on_track_changed = [this](const std::string &t,
                                  const std::string &a,
                                  const std::string &u,
                                  int64_t dur,
                                  bool expl,
                                  const std::string &id,
                                  const std::string &isrc) {
        on_track_changed(t, a, u, dur, expl, id, isrc);
    };
    scb.on_ready = [this] {
        display_.set_ready();
    };

    spirc_->start(std::move(scb));
    display_.set_connecting();
    state_.store(State::Ready);
    const std::string &canon = ap_->canonical_username();
    zeroconf_.set_active_user(canon);
    PLAT_LOGF("player: connected as '%s'", canon.c_str());
}

// ── Spirc callbacks ───────────────────────────────────────────────────────────

void Player::on_play(const std::string &track_uri, int position_ms) {
    PLAT_LOGF("player: load '%s' @%dms", track_uri.c_str(), position_ms);
    audio_->stop();
    spirc_playing_ = true;
    state_.store(State::Playing);
}

void Player::on_file_ready(const std::vector<uint8_t> &file_id,
                            const std::vector<uint8_t> &track_gid,
                            int pos_ms) {
    PLAT_LOG("player: file ready -- resolving CDN URL");

    spirc_->resolve_cdn(file_id, [this, file_id, track_gid, pos_ms]
                        (bool ok, std::string cdn_url) {
        if (!ok || cdn_url.empty()) {
            PLAT_LOG("player: CDN resolve failed");
            return;
        }
        PLAT_LOG("player: CDN URL resolved, requesting AES key");

        uint32_t seq;
        {
            std::lock_guard<std::mutex> lk(aes_mu_);
            seq              = aes_seq_++;
            pending_cdn_url_ = cdn_url;
            pending_file_id_ = file_id;
            pending_pos_ms_  = pos_ms;
        }

        std::vector<uint8_t> pkt;
        pkt.insert(pkt.end(), file_id.begin(),   file_id.end());
        pkt.insert(pkt.end(), track_gid.begin(), track_gid.end());
        pkt.push_back((seq >> 24) & 0xFF); pkt.push_back((seq >> 16) & 0xFF);
        pkt.push_back((seq >>  8) & 0xFF); pkt.push_back( seq        & 0xFF);
        pkt.push_back(0x00); pkt.push_back(0x00);

        {
            static const char hx[] = "0123456789abcdef";
            std::string fid_hex, gid_hex;
            for (uint8_t b : file_id)   { fid_hex += hx[b>>4]; fid_hex += hx[b&0xF]; }
            for (uint8_t b : track_gid) { gid_hex += hx[b>>4]; gid_hex += hx[b&0xF]; }
            PLAT_LOGF("player: RequestKey file=%s gid=%s seq=%u",
                      fid_hex.c_str(), gid_hex.c_str(), seq);
        }

        ap_->send_packet(Cmd::RequestKey, pkt);
    });
}

void Player::on_ap_packet(uint8_t cmd, std::vector<uint8_t> payload) {
    if (cmd == Cmd::AesKey) {
        if (payload.size() < 20) {
            PLAT_LOG("player: AesKey payload too short");
            return;
        }
        std::vector<uint8_t> key(payload.begin() + 4, payload.begin() + 20);

        std::string          cdn_url;
        std::vector<uint8_t> file_id;
        int pos;
        {
            std::lock_guard<std::mutex> lk(aes_mu_);
            cdn_url = pending_cdn_url_;
            file_id = pending_file_id_;
            pos     = pending_pos_ms_;
        }
        if (!cdn_url.empty()) {
            PLAT_LOG("player: AES key received -- starting audio");
            audio_->set_volume(volume_);
            audio_->play(cdn_url, key, file_id, pos);
        }
    } else if (cmd == Cmd::AesKeyError) {
        uint16_t ec = (payload.size() >= 6)
            ? (uint16_t)((payload[4] << 8) | payload[5]) : 0xFFFF;
        const char *reason = (ec == 0x0001) ? "NotEntitled (Spotify Premium required)"
                           : (ec == 0x0002) ? "not allowed"
                           :                  "unknown";
        PLAT_LOGF("player: AES key error code=0x%04X (%s)", (unsigned)ec, reason);
        // Do NOT auto-skip -- that creates an infinite skip loop when the whole
        // account lacks entitlement.  Show an error and let the user decide.
        display_.set_error(ec == 0x0001
            ? "Audio key denied -- Spotify Premium required"
            : "Audio key error -- cannot play track");
        audio_->stop();
    } else if (spirc_) {
        spirc_->on_packet(cmd, std::move(payload));
    }
}

void Player::on_seek(int pos_ms) {
    audio_->seek(pos_ms);
}

void Player::on_volume(int vol_pct) {
    volume_ = vol_pct;
    audio_->set_volume(vol_pct);
    display_.set_volume(vol_pct);
}

void Player::on_track_changed(const std::string &title, const std::string &artist,
                               const std::string &art_url, int64_t duration_ms, bool is_explicit,
                               const std::string &track_id, const std::string &isrc) {
    track_dur_ms_   = (int)std::min(duration_ms, (int64_t)INT_MAX);
    track_title_    = title;
    track_artist_   = artist;
    track_id_       = track_id;
    isrc_           = isrc;
    track_explicit_ = is_explicit;
    display_.set_track(title, artist, art_url, is_explicit);
}

// ── Switch controller buttons ─────────────────────────────────────────────────

void Player::handle_buttons(uint32_t trigger) {
    if (trigger & HidNpadButton_Plus) {
        volume_ = std::min(100, volume_ + 5);
        audio_->set_volume(volume_);
        display_.set_volume(volume_);
        if (spirc_) spirc_->notify(spirc_playing_, audio_->position_ms(), volume_);
    }
    if (trigger & HidNpadButton_Minus) {
        volume_ = std::max(0, volume_ - 5);
        audio_->set_volume(volume_);
        display_.set_volume(volume_);
        if (spirc_) spirc_->notify(spirc_playing_, audio_->position_ms(), volume_);
    }
    if ((trigger & HidNpadButton_R) && spirc_)
        spirc_->skip(true);
    if ((trigger & HidNpadButton_L) && spirc_)
        spirc_->skip(false);
    if ((trigger & HidNpadButton_ZR) && spirc_ && spirc_playing_) {
        int pos = std::min(audio_->position_ms() + 5000, INT_MAX);
        audio_->seek(pos);
        spirc_->seek_to(pos);
    }
    if ((trigger & HidNpadButton_ZL) && spirc_ && spirc_playing_) {
        int pos = std::max(audio_->position_ms() - 5000, 0);
        audio_->seek(pos);
        spirc_->seek_to(pos);
    }
    if (trigger & HidNpadButton_Up) {
        crystal_enabled_ = true;
        audio_->set_crystalizer(true, crystal_strength_);
        display_.set_crystalizer(true, crystal_strength_);
    }
    if (trigger & HidNpadButton_Down) {
        crystal_enabled_ = false;
        audio_->set_crystalizer(false, crystal_strength_);
        display_.set_crystalizer(false, crystal_strength_);
    }
    if (trigger & HidNpadButton_Right) {
        crystal_strength_ = std::min(25, crystal_strength_ + 1);
        audio_->set_crystalizer(crystal_enabled_, crystal_strength_);
        display_.set_crystalizer(crystal_enabled_, crystal_strength_);
    }
    if (trigger & HidNpadButton_Left) {
        crystal_strength_ = std::max(1, crystal_strength_ - 1);
        audio_->set_crystalizer(crystal_enabled_, crystal_strength_);
        display_.set_crystalizer(crystal_enabled_, crystal_strength_);
    }
    if (trigger & HidNpadButton_B)
        display_.toggle_controls();
    if ((trigger & HidNpadButton_X) && spirc_) {
        spirc_->toggle_shuffle();
        display_.set_shuffle(spirc_->shuffle());
    }
    if ((trigger & HidNpadButton_Y) && spirc_) {
        spirc_->toggle_repeat();
        display_.set_repeat(spirc_->repeat_mode());
    }
    if ((trigger & HidNpadButton_A) && spirc_) {
        int pos = audio_->position_ms();
        if (spirc_playing_) {
            spirc_playing_ = false;
            audio_->pause();
            display_.set_progress(pos, track_dur_ms_, false);
        } else {
            spirc_playing_ = true;
            audio_->resume();
            display_.set_progress(pos, track_dur_ms_, true);
        }
        spirc_->notify(spirc_playing_, pos, volume_);
    }
}

// ── Switch touchscreen ────────────────────────────────────────────────────────
//
// Touch zones (1280×720 framebuffer space):
//   Progress bar seek : x 40-1240, y 600-660
//   Album art tap     : x 40-400,  y 60-420  → play/pause
//   Swipe anywhere    : |dx| > 120, |dy| < 90 → next (right) / prev (left)

void Player::handle_touch() {
    HidTouchScreenState ts{};
    hidGetTouchScreenStates(&ts, 1);

    if (ts.count == 0) {
        if (touch_.active && !touch_.consumed && spirc_) {
            int dx = (int)touch_.cur_x - touch_.start_x;
            int dy = (int)touch_.cur_y - touch_.start_y;

            if (std::abs(dx) >= 120 && std::abs(dy) < 90) {
                if (dx > 0) spirc_->skip(true);
                else        spirc_->skip(false);
            } else if (touch_.start_x >= 40  && touch_.start_x <= 400 &&
                       touch_.start_y >= 60  && touch_.start_y <= 420 &&
                       std::abs(dx) < 30 && std::abs(dy) < 30) {
                int pos = audio_->position_ms();
                if (spirc_playing_) {
                    spirc_playing_ = false;
                    audio_->pause();
                    display_.set_progress(pos, track_dur_ms_, false);
                } else {
                    spirc_playing_ = true;
                    audio_->resume();
                    display_.set_progress(pos, track_dur_ms_, true);
                }
                spirc_->notify(spirc_playing_, pos, volume_);
            }
        }
        touch_ = {};
        return;
    }

    const int fx = (int)ts.touches[0].x;
    const int fy = (int)ts.touches[0].y;

    if (!touch_.active) {
        touch_.active   = true;
        touch_.consumed = false;
        touch_.start_x  = (int16_t)fx;
        touch_.start_y  = (int16_t)fy;
    }
    touch_.cur_x = (int16_t)fx;
    touch_.cur_y = (int16_t)fy;

    if (!touch_.consumed &&
        fy >= 600 && fy <= 660 &&
        fx >= 40  && fx <= 1240 &&
        spirc_ && track_dur_ms_ > 0) {
        float frac   = float(fx - 40) / 1200.0f;
        int   pos_ms = int(frac * track_dur_ms_);
        audio_->seek(pos_ms);
        spirc_->seek_to(pos_ms);
        touch_.consumed = true;
    }
}

} // namespace Connect