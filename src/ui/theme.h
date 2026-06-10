#pragma once
#include <SDL2/SDL.h>

namespace UI {
namespace Theme {

// ── Spotify palette ───────────────────────────────────────────────────────────
constexpr SDL_Color BG_TOP      = {66,  36, 100,  255};  // deep indigo — gradient top (diffs 60,30,90 all divide 720)
constexpr SDL_Color BG          = { 6,   6,  10,  255};  // near-black  — gradient bottom
constexpr SDL_Color SURFACE     = {40,  40,  40,  255};  // card background
constexpr SDL_Color ACCENT      = {30, 215,  96,  255};  // #1DB954 Spotify green
constexpr SDL_Color TEXT        = {255, 255, 255, 255};  // white
constexpr SDL_Color TEXT_DIM    = {179, 179, 179, 255};  // #B3B3B3
constexpr SDL_Color TEXT_HINT   = {100, 100, 100, 255};  // dark grey hint
constexpr SDL_Color BAR_BG      = {60,  60,  60,  255};  // progress bar background
constexpr SDL_Color ART_FILL    = {55,  55,  55,  255};  // placeholder art color

// ── Layout (1280×720 reference) ───────────────────────────────────────────────
constexpr int ART_SIZE          = 360;   // album art square size (px)
constexpr int ART_X             = 40;
constexpr int ART_Y             = 60;

constexpr int TEXT_X            = ART_X + ART_SIZE + 48;  // 448
constexpr int TITLE_Y           = 100;
constexpr int ARTIST_Y          = TITLE_Y + 70;            // 170

constexpr int BAR_X             = 40;
constexpr int BAR_Y             = 620;
constexpr int BAR_W             = 1200;
constexpr int BAR_H             = 9;

} // namespace Theme
} // namespace UI
