#pragma once
#include <mutex>

namespace Spotify {
// All HTTPS operations must hold this mutex.
// mbedTLS on Wii U is not safe for concurrent use across threads.
extern std::mutex g_http_mutex;
}
