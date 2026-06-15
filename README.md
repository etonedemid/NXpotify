# NXpotify

An unofficial [Spotify Connect](https://www.spotify.com/connect/) client for the Nintendo Switch, running as a homebrew NRO.

> **Requires a Spotify Premium account.**
> Not affiliated with or endorsed by Spotify AB.

![NXpotify now-playing screen](screenshot-1.jpg)

## Features

- **Spotify Connect** -- select "NXpotify" as your playback device from any Spotify app; control playback from your phone or PC
- **Full playlist context** -- skip and auto-advance work across entire playlists and albums
- **Shuffle & repeat** -- toggle on the Switch or from any connected Spotify app; state syncs both ways
- **Album art & track info** -- fetched automatically for the current track
- **Progress bar** with real-time position and timestamps
- **Spectrum visualizer** + dBFS loudness meter
- **Audio Crystalizer** -- harmonic-enhancement effect with adjustable strength
- **TV mode** -- Spotify TV-style layout with large album art when docked (1280x720)
- **Handheld mode** -- same layout with a button-hint strip at the bottom, switched automatically via `padIsHandheld()`

## Controls

Works with Joy-Con (handheld or attached), Pro Controller, and any other libnx-compatible controller.

| Button | Action |
|--------|--------|
| `A` | Play / Pause |
| `L` | Previous track |
| `R` | Next track |
| `+` | Volume +5 |
| `-` | Volume -5 |
| `ZL` / `ZR` | Seek -5 s / +5 s |
| `X` | Toggle shuffle |
| `Y` | Toggle repeat (off -> context -> track) |
| `Up` / `Down` | Crystalizer on / off |
| `Left` / `Right` | Crystalizer strength -1 / +1 |
| `B` | Show / hide controls overlay |

## Setup

NXpotify uses Spotify's Zeroconf (device discovery) protocol, so no credential tool is needed for the first run.

1. Copy `nxpotify.nro` to `SD:/switch/nxpotify/nxpotify.nro`
2. Launch the Homebrew Menu on your Switch and open **NXpotify**
3. On any Spotify app (phone, desktop, web), open the device picker and select **NXpotify**
4. Credentials are saved automatically to `SD:/spotify_saved_creds.bin` and reused on the next launch

### Credential tool (optional)

If zeroconf discovery does not work on your network, you can generate credentials manually with librespot:

```sh
librespot --name "nxpotify-setup" --cache /tmp/ls-cache
# open Spotify, select "nxpotify-setup", then Ctrl+C
python3 tools/make_creds.py /tmp/ls-cache/credentials.json
# copy the output spotify_saved_creds.bin to SD:/
```

## Building from source

### Prerequisites

- [devkitPro](https://devkitpro.org/wiki/Getting_Started) with the Switch dev package:

  ```sh
  dkp-pacman -S switch-dev
  ```

- **Tremor (integer Vorbis decoder)** -- install from portlibs or let the Makefile fall back to the vendored copy:

  ```sh
  dkp-pacman -S switch-libvorbisidec   # optional; Makefile detects it automatically
  ```

- **mbedTLS, libcurl, SDL2, SDL2_ttf** (all included in `switch-dev` or installable via dkp-pacman)

### Build

```sh
make          # produces nxpotify.nro
```

Deploy to a Switch running a nxlink server:

```sh
nxlink -a <switch-ip> -s nxpotify.nro
```

## Project layout

```
src/
  connect/    # AP handshake, Shannon cipher, Spirc/Connect state, audio pipeline, player
  discovery/  # Zeroconf / mDNS (makes the device visible to Spotify apps)
  ui/         # SDL2 renderer, spectrum visualizer, font baking, TV/handheld layout
  olv/        # Horizon social overlay stub
vendor/       # cJSON, stb_image, Tremor (fallback if portlib not installed)
tools/
  make_creds.py      # Convert librespot credentials.json -> spotify_saved_creds.bin
  test_ap.py         # AP packet capture/replay tool for debugging
  verify_dh.py       # DH key exchange verification
meta/                # App metadata and icon
```

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| "Audio key denied -- Spotify Premium required" | The connected account does not have Premium |
| Stuck on "Waiting for Spotify..." | Switch not reachable via mDNS; try the credential tool instead |
| Art never loads | Network firewall blocking HTTPS to `i.scdn.co` |
| App crashes on launch | Stack overflow in a background thread; file a bug with the nxlink log |

## Based on

Ported from [spotify-wiiu](https://github.com/Happynico7504/spotify-wiiu) by Nico Christmann.

## License

[MIT](LICENSE)
