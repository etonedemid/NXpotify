# NXpotify

An unofficial [Spotify Connect](https://www.spotify.com/connect/) client for the Nintendo Switch.
Based on https://github.com/Happynico7504/spotify-wiiu

> **Requires a Spotify Premium account.**
> Not affiliated with or endorsed by Spotify AB.

Tap the cover art to pause, swipe right to skip, left to rewind, tap on timeline to skip to the segment. 

Enjoy!

![NXpotify now-playing screen](screenshot-1.jpg)
<img width="1280" height="720" alt="2026061520453000-9B58DE145B4A9B8A7451479606CF81B9" src="https://github.com/user-attachments/assets/1d43d1ac-5df4-47e1-88bd-f191d57bbbec" />
<img width="1280" height="720" alt="2026061520425100-9B58DE145B4A9B8A7451479606CF81B9" src="https://github.com/user-attachments/assets/25845789-3e23-401d-b40f-5d85b1837846" />


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
make         
```

Deploy to a Switch running a nxlink server:

```sh
nxlink -a <switch-ip> -s nxpotify.nro
```

Ported from [spotify-wiiu](https://github.com/Happynico7504/spotify-wiiu) by Nico Christmann.

## License

[MIT](LICENSE)
