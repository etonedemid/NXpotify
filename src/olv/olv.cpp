#include "olv.h"

// OLV (Miiverse / Roséverse) is WiiU only. All functions are stubbed 

namespace OLV {

std::vector<Pack> fetch_stamp_packs()                                 { return {}; }
int  cached_stamp_count(const std::string &)                          { return 0; }
int  download_stamp_pack(const Pack &)                                { return 0; }
void delete_stamp_pack(const std::string &)                           {}
void load_stamp_pack(const std::string &)                             {}
void save_selected_pack(const std::string &)                          {}
std::string load_selected_pack()                                      { return "none"; }

bool init()         { return false; }
void shutdown()     {}
bool is_available() { return false; }

std::vector<Post> fetch_posts(uint32_t, uint32_t, const std::string &) { return {}; }

void open_post_applet(const std::string &, bool,
                      const std::string &, const std::string &,
                      uint32_t, uint32_t) {}

void open_overlay(const std::string &) {}

} // namespace OLV
