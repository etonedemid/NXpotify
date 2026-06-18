#pragma once
#include <SDL2/SDL.h>

namespace UI {
namespace Theme {

// ── Spotify palette ───────────────────────────────────────────────────────────
constexpr SDL_Color BG_TOP      = {40,  40,  40,  255};  // dark gray   -- gradient top
constexpr SDL_Color BG          = {15, 20,  15,  255};  // darker gray    - gradient bottom
constexpr SDL_Color SURFACE     = {40,  40,  40,  255};  // card background
constexpr SDL_Color ACCENT      = {180, 180, 180, 255};
constexpr SDL_Color TEXT        = {255, 255, 255, 255};  // white
constexpr SDL_Color TEXT_DIM    = {180, 180, 180, 255};
constexpr SDL_Color TEXT_HINT   = {100, 100, 100, 255};  // dark grey hint
constexpr SDL_Color BAR_BG      = {60,  60,  60,  255};  // progress bar background
constexpr SDL_Color ART_FILL    = {55,  55,  55,  255};  // placeholder art color

// ── Layout (1280x720 reference, Spotify TV style) ─────────────────────────────
constexpr int ART_SIZE          = 420;   // album art square
constexpr int ART_X             = 60;
constexpr int ART_Y             = 60;

constexpr int TEXT_X            = ART_X + ART_SIZE + 40;
constexpr int ARTIST_Y          = 60;   // small muted row above title
constexpr int TITLE_Y           = ARTIST_Y + 54;

constexpr int BAR_X             = 60;
constexpr int BAR_Y             = 572;
constexpr int BAR_W             = 1160;
constexpr int BAR_H             = 16;

// Transport icon row (drawn, not text) center-x and center-y
constexpr int TRANSPORT_Y       = 625;
// Status badges (SHUF/REP/XTAL) row
constexpr int STATUS_Y          = 672;

// ── Layout presets ────────────────────────────────────────────────────────────
struct Layout {
    const char *name;
    int art_x, art_y, art_size;
};

constexpr Layout LAYOUTS[] = {
    { "Classic", 60,  60, 420 },
    { "Big Art", 40,  40, 520 },
    { "Compact", 40, 110, 280 },
};
constexpr int LAYOUT_COUNT = 3;

// ── Accent color presets (index 5 = use art color) ───────────────────────────
constexpr SDL_Color COLOR_PRESETS[5] = {
    {180, 180, 180, 255},   // Gray (default)
    { 30, 215,  96, 255},   // Green
    {100, 160, 255, 255},   // Blue
    {255, 155,  50, 255},   // Orange
    {180,  90, 240, 255},   // Purple
};

} // namespace Theme
} // namespace UI
