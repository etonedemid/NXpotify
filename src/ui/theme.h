#pragma once
#include <SDL2/SDL.h>

namespace UI {
namespace Theme {

// ── Spotify palette ───────────────────────────────────────────────────────────
constexpr SDL_Color BG_TOP      = {40,  40,  40,  255};  // dark gray   -- gradient top
constexpr SDL_Color BG          = {15, 20,  15,  255};  // darker gray    - gradient bottom
constexpr SDL_Color SURFACE     = {40,  40,  40,  255};  // card background
constexpr SDL_Color ACCENT      = {30, 215,  96,  255};  // #1DB954 Spotify green
constexpr SDL_Color TEXT        = {255, 255, 255, 255};  // white
constexpr SDL_Color TEXT_DIM    = {179, 179, 179, 255};  // #B3B3B3
constexpr SDL_Color TEXT_HINT   = {100, 100, 100, 255};  // dark grey hint
constexpr SDL_Color BAR_BG      = {60,  60,  60,  255};  // progress bar background
constexpr SDL_Color ART_FILL    = {55,  55,  55,  255};  // placeholder art color

// ── Layout (1280x720 reference, Spotify TV style) ─────────────────────────────
constexpr int ART_SIZE          = 420;   // album art square
constexpr int ART_X             = 60;
constexpr int ART_Y             = 140;   // vertically centered ~140-560

constexpr int TEXT_X            = ART_X + ART_SIZE + 60;  // 540
constexpr int ARTIST_Y          = 155;   // small muted row above title
constexpr int TITLE_Y           = ARTIST_Y + 54;          // 209

constexpr int BAR_X             = 60;
constexpr int BAR_Y             = 572;
constexpr int BAR_W             = 1160;
constexpr int BAR_H             = 8;

// Transport icon row (drawn, not text) center-x and center-y
constexpr int TRANSPORT_Y       = 625;
// Status badges (SHUF/REP/XTAL) row
constexpr int STATUS_Y          = 672;

} // namespace Theme
} // namespace UI
