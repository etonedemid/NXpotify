#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <atomic>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <sys/select.h>
#include <curl/curl.h>

// Minimal TLS 1.3 client using mbedTLS 2.28 crypto primitives.
// Implements just enough to connect to Spotify's AP:
//   X25519 + secp256r1 key exchange, TLS_AES_128_GCM_SHA256,
//   no certificate verification.
// send() encrypts and writes directly -- no pre-write recv check
// (which is what deadlocks NSSL when the server sends no NewSessionTicket).

class TLS13Client {
public:
    TLS13Client();
    ~TLS13Client();

    // Complete TLS 1.3 handshake on an already-connected blocking TCP socket.
    bool connect(int fd, const char* hostname);

    // Complete TLS 1.3 handshake using curl_easy_send/recv for raw I/O.
    // curl's socket mechanism works for outbound TCP on Wii U where POSIX
    // recv() is broken. The TCP connection must already be established in curl.
    bool connect_via_curl(CURL *curl, const char* hostname);

    // Send application data (encrypted).
    bool send(const uint8_t* buf, size_t len);

    // Receive exactly len bytes of application data.
    // Polls fd_ with 2-second timeout so stop can be checked between polls.
    bool recv_exact(uint8_t* buf, size_t len, const std::atomic<bool>& stop);

private:
    int   fd_   = -1;
    CURL *curl_ = nullptr;   // set by connect_via_curl; used for send/recv I/O

    mbedtls_entropy_context  entropy_{};
    mbedtls_ctr_drbg_context drbg_{};
    mbedtls_ecdh_context     ecdh_x25519_{};
    mbedtls_ecdh_context     ecdh_p256_{};

    int      chosen_group_ = 0;   // 0x001d=x25519, 0x0017=secp256r1
    uint8_t  send_key_[16]{};
    uint8_t  send_iv_[12]{};
    uint8_t  recv_key_[16]{};
    uint8_t  recv_iv_[12]{};
    uint64_t send_seq_ = 0;
    uint64_t recv_seq_ = 0;

    std::vector<uint8_t> app_buf_;   // decrypted application data not yet consumed

    bool do_handshake(const char* hostname);
};
