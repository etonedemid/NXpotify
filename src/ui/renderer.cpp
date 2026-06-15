#include "renderer.h"
#include <cstring>
#include <cmath>
#include <sstream>
#include "platform.h"

namespace UI {

bool Renderer::init(SDL_Renderer *r) {
    renderer_ = r;
    return true;
}

void Renderer::destroy() {
    if (font_sm)    { TTF_CloseFont(font_sm);    font_sm    = nullptr; }
    if (font_md)    { TTF_CloseFont(font_md);    font_md    = nullptr; }
    if (font_lg)    { TTF_CloseFont(font_lg);    font_lg    = nullptr; }
    if (font_title) { TTF_CloseFont(font_title); font_title = nullptr; }
}

void Renderer::fill_rect(int x, int y, int w, int h, SDL_Color col) {
    SDL_SetRenderDrawColor(renderer_, col.r, col.g, col.b, col.a);
    SDL_Rect rect = { x, y, w, h };
    SDL_RenderFillRect(renderer_, &rect);
}

void Renderer::draw_rect(int x, int y, int w, int h, SDL_Color col, int thickness) {
    SDL_SetRenderDrawColor(renderer_, col.r, col.g, col.b, col.a);
    for (int i = 0; i < thickness; i++) {
        SDL_Rect rect = { x + i, y + i, w - 2*i, h - 2*i };
        SDL_RenderDrawRect(renderer_, &rect);
    }
}

void Renderer::fill_rounded_rect(int x, int y, int w, int h, int r, SDL_Color col) {
    SDL_SetRenderDrawColor(renderer_, col.r, col.g, col.b, col.a);
    SDL_Rect center = { x + r, y,     w - 2*r, h     };
    SDL_Rect left   = { x,     y + r, r,       h - 2*r };
    SDL_Rect right  = { x + w - r, y + r, r,   h - 2*r };
    SDL_RenderFillRect(renderer_, &center);
    SDL_RenderFillRect(renderer_, &left);
    SDL_RenderFillRect(renderer_, &right);
    fill_circle(x + r,     y + r,     r, col);
    fill_circle(x + w - r, y + r,     r, col);
    fill_circle(x + r,     y + h - r, r, col);
    fill_circle(x + w - r, y + h - r, r, col);
}

void Renderer::fill_circle(int cx, int cy, int radius, SDL_Color col) {
    SDL_SetRenderDrawColor(renderer_, col.r, col.g, col.b, col.a);
    int r2 = radius * radius;
    for (int dy = -radius; dy <= radius; dy++) {
        int dx = (int)sqrt((double)(r2 - dy * dy));
        SDL_RenderDrawLine(renderer_, cx - dx, cy + dy, cx + dx, cy + dy);
    }
}

int Renderer::draw_text(int x, int y, const std::string &text, SDL_Color col,
                        TTF_Font *font) {
    if (!font) font = font_md;
    if (!font || text.empty()) return 0;
    SDL_Surface *surf = TTF_RenderUTF8_Blended(font, text.c_str(), col);
    if (!surf) return 0;
    SDL_Texture *tex = SDL_CreateTextureFromSurface(renderer_, surf);
    int w = surf->w, h = surf->h;
    SDL_FreeSurface(surf);
    if (!tex) return 0;
    SDL_Rect dst = { x, y, w, h };
    SDL_RenderCopy(renderer_, tex, nullptr, &dst);
    SDL_DestroyTexture(tex);
    return w;
}

int Renderer::draw_text_right(int right_x, int y, const std::string &text,
                               SDL_Color col, TTF_Font *font) {
    if (!font) font = font_md;
    int w = text_width(text, font);
    draw_text(right_x - w, y, text, col, font);
    return right_x - w;
}

int Renderer::draw_text_clipped(int x, int y, const std::string &text,
                                 SDL_Color col, int max_width, TTF_Font *font) {
    if (!font) font = font_md;
    if (!font || text.empty()) return 0;
    if (text_width(text, font) <= max_width)
        return draw_text(x, y, text, col, font);

    // Binary-search for longest prefix that fits with "…"
    std::string ellipsis = text;
    while (ellipsis.size() > 1) {
        // Step back by one UTF-8 character (naive byte-level is fine for display)
        ellipsis.pop_back();
        std::string candidate = ellipsis + "…";
        if (text_width(candidate, font) <= max_width)
            return draw_text(x, y, candidate, col, font);
    }
    return draw_text(x, y, "…", col, font);
}

int Renderer::text_width(const std::string &text, TTF_Font *font) {
    if (!font) font = font_md;
    if (!font || text.empty()) return 0;
    int w = 0, h = 0;
    TTF_SizeUTF8(font, text.c_str(), &w, &h);
    return w;
}

int Renderer::text_height(TTF_Font *font) {
    if (!font) font = font_md;
    if (!font) return 16;
    return TTF_FontHeight(font);
}

std::vector<std::string> Renderer::wrap_text(const std::string &text,
                                              int max_width, TTF_Font *font) {
    if (!font) font = font_md;
    std::vector<std::string> lines;
    if (!font || text.empty()) return lines;

    auto flush = [&](const std::string &para) {
        if (para.empty()) { lines.push_back(""); return; }
        std::istringstream iss(para);
        std::string word, line;
        while (iss >> word) {
            std::string test = line.empty() ? word : (line + " " + word);
            int w = 0, h = 0;
            TTF_SizeUTF8(font, test.c_str(), &w, &h);
            if (w <= max_width) {
                line = test;
            } else {
                if (!line.empty()) lines.push_back(line);
                TTF_SizeUTF8(font, word.c_str(), &w, &h);
                if (w > max_width) {
                    std::string partial;
                    for (char c : word) {
                        std::string t2 = partial + c;
                        TTF_SizeUTF8(font, t2.c_str(), &w, &h);
                        if (w > max_width) { lines.push_back(partial); partial = std::string(1, c); }
                        else partial = t2;
                    }
                    line = partial;
                } else {
                    line = word;
                }
            }
        }
        if (!line.empty()) lines.push_back(line);
    };

    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) { flush(text.substr(pos)); break; }
        flush(text.substr(pos, nl - pos));
        pos = nl + 1;
    }
    return lines;
}

} // namespace UI
